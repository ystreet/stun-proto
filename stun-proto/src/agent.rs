// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN agent
//!
//! A STUN Agent that follows the procedures of [RFC5389] and [RFC8489] and is implemented with the
//! sans-IO pattern. This agent does no IO processing and operates solely on inputs it is
//! provided.
//!
//! [RFC8489]: https://tools.ietf.org/html/rfc8489
//! [RFC5389]: https://tools.ietf.org/html/rfc5389

use core::net::SocketAddr;
use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use crate::Instant;

use stun_types::attribute::*;
use stun_types::data::Data;
use stun_types::message::*;

use stun_types::TransportType;

use tracing::{debug, trace, warn};

static STUN_AGENT_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Implementation of a STUN agent
#[derive(Debug)]
pub struct StunAgent {
    id: usize,
    transport: TransportType,
    local_addr: SocketAddr,
    remote_addr: Option<SocketAddr>,
    validated_peers: BTreeSet<SocketAddr>,
    outstanding_requests: BTreeMap<TransactionId, StunRequestState>,
    local_credentials: Option<MessageIntegrityCredentials>,
    remote_credentials: Option<MessageIntegrityCredentials>,
}

/// Builder struct for a [`StunAgent`]
#[derive(Debug)]
pub struct StunAgentBuilder {
    transport: TransportType,
    local_addr: SocketAddr,
    remote_addr: Option<SocketAddr>,
}

impl StunAgentBuilder {
    /// Set the remote address the [`StunAgent`] will be configured to only send data to
    pub fn remote_addr(mut self, addr: SocketAddr) -> Self {
        self.remote_addr = Some(addr);
        self
    }

    /// Build the [`StunAgent`]
    pub fn build(self) -> StunAgent {
        let id = STUN_AGENT_COUNT.fetch_add(1, Ordering::SeqCst);
        StunAgent {
            id,
            transport: self.transport,
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            validated_peers: Default::default(),
            outstanding_requests: Default::default(),
            local_credentials: None,
            remote_credentials: None,
        }
    }
}

impl StunAgent {
    /// Create a new [`StunAgentBuilder`]
    pub fn builder(transport: TransportType, local_addr: SocketAddr) -> StunAgentBuilder {
        StunAgentBuilder {
            transport,
            local_addr,
            remote_addr: None,
        }
    }

    /// The [`TransportType`] of this [`StunAgent`]
    pub fn transport(&self) -> TransportType {
        self.transport
    }

    /// The local address of this [`StunAgent`]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The remote address of this [`StunAgent`]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Set the local credentials that all messages should be signed with
    pub fn set_local_credentials(&mut self, credentials: MessageIntegrityCredentials) {
        self.local_credentials = Some(credentials)
    }

    /// The local credentials that all messages should be signed with
    pub fn local_credentials(&self) -> Option<MessageIntegrityCredentials> {
        self.local_credentials.clone()
    }

    /// Set the remote credentials that all messages should be signed with
    pub fn set_remote_credentials(&mut self, credentials: MessageIntegrityCredentials) {
        self.remote_credentials = Some(credentials)
    }

    /// The remote credentials that all messages should be signed with
    pub fn remote_credentials(&self) -> Option<MessageIntegrityCredentials> {
        self.remote_credentials.clone()
    }

    /// Perform any operations needed to be able to send data to a peer
    pub fn send_data<T: AsRef<[u8]>>(&self, bytes: T, to: SocketAddr) -> Transmit<T> {
        send_data(self.transport, bytes, self.local_addr, to)
    }

    /// Perform any operations needed to be able to send a [`Message`] to a peer.
    ///
    /// The returned [`Transmit`] must be sent to the respective peer after this call.
    #[tracing::instrument(name = "stun_agent_send", skip(self, msg))]
    pub fn send<T: AsRef<[u8]>>(
        &mut self,
        msg: T,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<T>, StunError> {
        let data = msg.as_ref();
        let hdr = MessageHeader::from_bytes(data)?;
        assert!(!hdr.get_type().has_class(MessageClass::Request));
        Ok(Transmit::new(msg, self.transport, self.local_addr, to))
    }

    /// Perform any operations needed to be able to send a request [`Message`] to a peer.
    ///
    /// The returned [`Transmit`] must be sent to the respective peer after this call.
    #[tracing::instrument(name = "stun_agent_send", skip(self, msg))]
    pub fn send_request<'a, T: AsRef<[u8]>>(
        &'a mut self,
        msg: T,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Data<'a>>, StunError> {
        let data = msg.as_ref();
        let hdr = MessageHeader::from_bytes(data)?;
        assert!(hdr.get_type().has_class(MessageClass::Request));
        let transaction_id = hdr.transaction_id();
        let state = match self.outstanding_requests.entry(transaction_id) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                let has_credentials = MessageAttributesIter::new(data).any(|(_offset, attr)| {
                    [MessageIntegrity::TYPE, MessageIntegritySha256::TYPE]
                        .contains(&attr.get_type())
                });
                entry.insert(StunRequestState::new(
                    msg,
                    self.transport,
                    self.local_addr,
                    to,
                    transaction_id,
                    has_credentials,
                ))
            }
            alloc::collections::btree_map::Entry::Occupied(_entry) => {
                return Err(StunError::AlreadyInProgress);
            }
        };
        let Some(transmit) = state.poll_transmit(now) else {
            unreachable!();
        };
        Ok(Transmit::new(
            Data::from(transmit.data),
            transmit.transport,
            transmit.from,
            transmit.to,
        ))
    }

    /// Returns whether this agent has received or sent a STUN message with this peer. Failure may
    /// be the result of an attacker and the caller must drop any non-STUN data received before this
    /// functions returns `true`.
    ///
    /// If non-STUN data is received over a TCP connection from an unvalidated peer, the caller
    /// must immediately close the TCP connection.
    pub fn is_validated_peer(&self, remote_addr: SocketAddr) -> bool {
        self.validated_peers.contains(&remote_addr)
    }

    #[tracing::instrument(
        name = "stun_validated_peer"
        skip(self),
        fields(stun_id = self.id)
    )]
    fn validated_peer(&mut self, addr: SocketAddr) {
        if !self.validated_peers.contains(&addr) {
            debug!("validated peer {:?}", addr);
            self.validated_peers.insert(addr);
        }
    }

    /// Provide data received on a socket from a peer for handling by the [`StunAgent`].
    /// The returned value indicates what the caller must do with the data.
    ///
    /// If this function returns [`HandleStunReply::ValidatedStunResponse`], then this agent needs to be
    /// [`poll()`](StunAgent::poll)ed again.
    ///
    /// If this function returns [`HandleStunReply::UnvalidatedStunResponse`], and the user handles
    /// the request in some way, then [`StunAgent::remove_outstanding_request()`] must be called
    /// and this agent needs to be [`poll()`](StunAgent::poll)ed again.
    #[tracing::instrument(
        name = "stun_handle_message"
        skip(self, msg, from),
        fields(
            transaction_id = %msg.transaction_id(),
        )
    )]
    pub fn handle_stun<'a>(&mut self, msg: Message<'a>, from: SocketAddr) -> HandleStunReply<'a> {
        if msg.is_response() {
            let Some(request) = self.take_outstanding_request(&msg.transaction_id()) else {
                trace!("original request disappeared -> ignoring response");
                return HandleStunReply::Drop;
            };
            // only validate response if the original request had credentials
            if request.request_had_credentials {
                if let Some(remote_creds) = &self.remote_credentials {
                    match msg.validate_integrity(remote_creds) {
                        Ok(_) => {
                            self.validated_peer(from);
                            HandleStunReply::ValidatedStunResponse(msg)
                        }
                        Err(e) => {
                            debug!("message failed integrity check: {:?}", e);
                            self.outstanding_requests
                                .insert(msg.transaction_id(), request);
                            HandleStunReply::UnvalidatedStunResponse(msg)
                        }
                    }
                } else {
                    debug!("no remote credentials");
                    self.outstanding_requests
                        .insert(msg.transaction_id(), request);
                    HandleStunReply::UnvalidatedStunResponse(msg)
                }
            } else {
                // original message didn't have integrity, reply doesn't need to either
                self.validated_peer(from);
                HandleStunReply::ValidatedStunResponse(msg)
            }
        } else {
            self.validated_peer(from);
            HandleStunReply::IncomingStun(msg)
        }
    }

    #[tracing::instrument(
        skip(self, transaction_id),
        fields(transaction_id = %transaction_id)
    )]
    fn take_outstanding_request(
        &mut self,
        transaction_id: &TransactionId,
    ) -> Option<StunRequestState> {
        if let Some(request) = self.outstanding_requests.remove(transaction_id) {
            trace!("removing request");
            Some(request)
        } else {
            trace!("no outstanding request");
            None
        }
    }

    /// Remove an outstanding request from being handled any further.
    ///
    /// Particularly useful when handling [`HandleStunReply::UnvalidatedStunResponse`]
    ///
    /// Returns whether the request was successfully removed.
    pub fn remove_outstanding_request(&mut self, transaction_id: TransactionId) -> bool {
        self.take_outstanding_request(&transaction_id).is_some()
    }

    /// Retrieve a reference to an outstanding STUN request. Outstanding requests are kept until
    /// either:
    /// - [`handle_stun()`](StunAgent::handle_stun) receives (and validates) the associated
    ///   response,
    /// - [`remove_outstanding_request()`](StunAgent::remove_outstanding_request) is called, or
    /// - [`poll()`](StunAgent::poll) returns [`StunAgentPollRet::TransactionCancelled`] or
    ///   [`StunAgentPollRet::TransactionTimedOut`] for the request.
    pub fn request_transaction(&self, transaction_id: TransactionId) -> Option<StunRequest<'_>> {
        if self.outstanding_requests.contains_key(&transaction_id) {
            Some(StunRequest {
                agent: self,
                transaction_id,
            })
        } else {
            None
        }
    }

    /// Retrieve a mutable reference to an outstanding STUN request. Outstanding requests are kept
    /// until either:
    /// - [`handle_stun()`](StunAgent::handle_stun) receives (and validates) the associated
    ///   response,
    /// - [`remove_outstanding_request()`](StunAgent::remove_outstanding_request) is called, or
    /// - [`poll()`](StunAgent::poll) returns [`StunAgentPollRet::TransactionCancelled`] or
    ///   [`StunAgentPollRet::TransactionTimedOut`] for the request.
    pub fn mut_request_transaction(
        &mut self,
        transaction_id: TransactionId,
    ) -> Option<StunRequestMut<'_>> {
        if self.outstanding_requests.contains_key(&transaction_id) {
            Some(StunRequestMut {
                agent: self,
                transaction_id,
            })
        } else {
            None
        }
    }

    fn mut_request_state(
        &mut self,
        transaction_id: TransactionId,
    ) -> Option<&mut StunRequestState> {
        self.outstanding_requests.get_mut(&transaction_id)
    }

    fn request_state(&self, transaction_id: TransactionId) -> Option<&StunRequestState> {
        self.outstanding_requests.get(&transaction_id)
    }

    /// Poll the agent for making further progress on any outstanding requests. The returned value
    /// indicates the current state and anything the caller needs to perform.
    ///
    /// Upon expiry of the timer from [`StunAgentPollRet::WaitUntil`],
    /// [`poll_transmit()`](StunAgent::poll_transmit) must be called.
    #[tracing::instrument(
        name = "stun_agent_poll"
        level = "debug",
        skip(self),
    )]
    pub fn poll(&mut self, now: Instant) -> StunAgentPollRet {
        let mut lowest_wait = now + Duration::from_secs(3600);
        let mut timeout = None;
        let mut cancelled = None;
        for (transaction_id, request) in self.outstanding_requests.iter_mut() {
            debug_assert_eq!(transaction_id, &request.transaction_id);
            match request.poll(now) {
                StunRequestPollRet::Cancelled => {
                    cancelled = Some(*transaction_id);
                    break;
                }
                StunRequestPollRet::WaitUntil(wait_until) => {
                    if wait_until < lowest_wait {
                        lowest_wait = wait_until;
                    }
                }
                StunRequestPollRet::TimedOut => {
                    timeout = Some(*transaction_id);
                    break;
                }
            }
        }
        if let Some(transaction) = timeout {
            if let Some(_state) = self.outstanding_requests.remove(&transaction) {
                return StunAgentPollRet::TransactionTimedOut(transaction);
            }
        }
        if let Some(transaction) = cancelled {
            if let Some(_state) = self.outstanding_requests.remove(&transaction) {
                return StunAgentPollRet::TransactionCancelled(transaction);
            }
        }
        StunAgentPollRet::WaitUntil(lowest_wait)
    }

    /// Poll for any transmissions that may need to be performed.
    #[tracing::instrument(
        name = "stun_agent_poll_transmit"
        level = "debug",
        skip(self),
    )]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<&[u8]>> {
        self.outstanding_requests
            .values_mut()
            .filter_map(|request| request.poll_transmit(now))
            .next()
    }
}

/// Return value for [`StunAgent::poll`]
#[derive(Debug)]
pub enum StunAgentPollRet {
    /// An oustanding transaction timed out and has been removed from the agent.
    TransactionTimedOut(TransactionId),
    /// An oustanding transaction was cancelled and has been removed from the agent.
    TransactionCancelled(TransactionId),
    /// Wait until the specified time has passed.
    WaitUntil(Instant),
}

fn send_data<T: AsRef<[u8]>>(
    transport: TransportType,
    bytes: T,
    from: SocketAddr,
    to: SocketAddr,
) -> Transmit<T> {
    Transmit::new(bytes, transport, from, to)
}

/// A piece of data that needs to, or has been transmitted
#[derive(Debug)]
pub struct Transmit<T: AsRef<[u8]>> {
    /// The data blob
    pub data: T,
    /// The transport for the transmission
    pub transport: TransportType,
    /// The source address of the transmission
    pub from: SocketAddr,
    /// The destination address of the transmission
    pub to: SocketAddr,
}

impl<T: AsRef<[u8]>> core::fmt::Display for Transmit<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Transmit({}: {} -> {}) of {} bytes",
            self.transport,
            self.from,
            self.to,
            self.data.as_ref().len()
        )
    }
}

impl<T: AsRef<[u8]>> Transmit<T> {
    /// Construct a new [`Transmit`] with the specifid data and 5-tuple.
    pub fn new(data: T, transport: TransportType, from: SocketAddr, to: SocketAddr) -> Self {
        Self {
            data,
            transport,
            from,
            to,
        }
    }

    /// Reinterpret the data of a [`Transmit`] into a different type.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_proto::agent::Transmit;
    /// # use stun_proto::types::TransportType;
    /// # use core::net::SocketAddr;
    /// let local_addr = "10.0.0.1:1000".parse().unwrap();
    /// let remote_addr = "10.0.0.2:2000".parse().unwrap();
    /// let slice = [42; 8];
    /// let transmit = Transmit::new(slice.clone(), TransportType::Udp, local_addr, remote_addr);
    /// // change the data type of the `Transmit` into a `Vec<u8>`.
    /// let transmit = transmit.reinterpret_data(|data| data.to_vec());
    /// # assert_eq!(transmit.transport, TransportType::Udp);
    /// # assert_eq!(transmit.from, local_addr);
    /// # assert_eq!(transmit.to, remote_addr);
    /// assert_eq!(transmit.data, slice.as_slice());
    /// ```
    pub fn reinterpret_data<O: AsRef<[u8]>, F: FnOnce(T) -> O>(self, f: F) -> Transmit<O> {
        Transmit {
            data: f(self.data),
            transport: self.transport,
            from: self.from,
            to: self.to,
        }
    }
}

impl Transmit<Data<'_>> {
    /// Construct a new owned [`Transmit`] from a provided [`Transmit`]
    pub fn into_owned<'b>(self) -> Transmit<Data<'b>> {
        self.reinterpret_data(|data| data.into_owned())
    }
}

/// Return value for [`StunRequest::poll`]
#[derive(Debug)]
enum StunRequestPollRet {
    /// Wait until the specified time has passed
    WaitUntil(Instant),
    /// The request has been cancelled and will not make further progress
    Cancelled,
    /// The request timed out.
    TimedOut,
}

#[derive(Debug)]
struct StunRequestState {
    transaction_id: TransactionId,
    request_had_credentials: bool,
    bytes: Vec<u8>,
    transport: TransportType,
    from: SocketAddr,
    to: SocketAddr,
    timeouts_ms: Vec<u64>,
    last_retransmit_timeout_ms: u64,
    recv_cancelled: bool,
    send_cancelled: bool,
    timeout_i: usize,
    last_send_time: Option<Instant>,
}

impl StunRequestState {
    fn new<T: AsRef<[u8]>>(
        request: T,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        transaction_id: TransactionId,
        has_credentials: bool,
    ) -> Self {
        let data = request.as_ref();
        let (timeouts_ms, last_retransmit_timeout_ms) = if transport == TransportType::Tcp {
            (vec![], 39500)
        } else {
            (vec![500, 1000, 2000, 4000, 8000, 16000], 8000)
        };
        Self {
            transaction_id,
            bytes: data.to_vec(),
            transport,
            from,
            to,
            request_had_credentials: has_credentials,
            timeouts_ms,
            timeout_i: 0,
            last_retransmit_timeout_ms,
            recv_cancelled: false,
            send_cancelled: false,
            last_send_time: None,
        }
    }

    #[tracing::instrument(skip(self, now), level = "trace", ret)]
    fn next_send_time(&self, now: Instant) -> Option<Instant> {
        let Some(last_send) = self.last_send_time else {
            trace!("not sent yet -> send immediately");
            return Some(now);
        };
        if self.timeout_i >= self.timeouts_ms.len() {
            let next_send = last_send + Duration::from_millis(self.last_retransmit_timeout_ms);
            trace!("final retransmission, final timeout ends at {next_send:?}");
            if next_send > now {
                return Some(next_send);
            }
            return None;
        }
        let next_send = last_send + Duration::from_millis(self.timeouts_ms[self.timeout_i]);
        Some(next_send)
    }

    #[tracing::instrument(
        name = "stun_request_poll"
        level = "debug",
        ret,
        skip(self, now),
        fields(transaction_id = %self.transaction_id),
    )]
    fn poll(&mut self, now: Instant) -> StunRequestPollRet {
        if self.recv_cancelled {
            return StunRequestPollRet::Cancelled;
        }
        // TODO: account for TCP connect in timeout
        let Some(next_send) = self.next_send_time(now) else {
            return StunRequestPollRet::TimedOut;
        };
        if next_send >= now {
            if self.send_cancelled && self.timeout_i >= self.timeouts_ms.len() {
                // this cancellation may need a different value
                return StunRequestPollRet::Cancelled;
            }
            return StunRequestPollRet::WaitUntil(next_send);
        }
        StunRequestPollRet::WaitUntil(now)
    }

    #[tracing::instrument(
        name = "stun_request_poll_transmit",
        skip(self, now),
        fields(transaction_id = %self.transaction_id)
    )]
    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<&[u8]>> {
        if self.recv_cancelled {
            return None;
        };
        let next_send = self.next_send_time(now)?;

        if next_send > now {
            return None;
        }
        if self.last_send_time.is_some() {
            self.timeout_i += 1;
        }
        self.last_send_time = Some(now);
        if self.send_cancelled {
            return None;
        };
        trace!(
            "sending {} bytes over {:?} from {:?} to {:?}",
            self.bytes.len(),
            self.transport,
            self.from,
            self.to
        );
        Some(send_data(
            self.transport,
            self.bytes.as_slice(),
            self.from,
            self.to,
        ))
    }
}

/// A STUN Request
#[derive(Debug, Clone)]
pub struct StunRequest<'a> {
    agent: &'a StunAgent,
    transaction_id: TransactionId,
}

impl StunRequest<'_> {
    /// The remote address the request is sent to
    pub fn peer_address(&self) -> SocketAddr {
        let state = self.agent.request_state(self.transaction_id).unwrap();
        state.to
    }
}

/// A STUN Request
#[derive(Debug)]
pub struct StunRequestMut<'a> {
    agent: &'a mut StunAgent,
    transaction_id: TransactionId,
}

impl StunRequestMut<'_> {
    /// The remote address the request is sent to
    pub fn peer_address(&self) -> SocketAddr {
        let state = self.agent.request_state(self.transaction_id).unwrap();
        state.to
    }

    /// Do not retransmit further. This will still allow for a reply to occur within the configured
    /// timeouts, but will never send a retransmission. If no response is received, this will cause
    /// [`StunAgent::poll()`] to return [`StunAgentPollRet::TransactionCancelled`] for this request.
    pub fn cancel_retransmissions(&mut self) {
        if let Some(state) = self.agent.mut_request_state(self.transaction_id) {
            state.send_cancelled = true;
        }
    }

    /// Do not wait for any kind of response. This will cause [`StunAgent::poll()`] to return
    /// [`StunAgentPollRet::TransactionCancelled`] for this request.
    pub fn cancel(&mut self) {
        if let Some(state) = self.agent.mut_request_state(self.transaction_id) {
            state.send_cancelled = true;
            state.recv_cancelled = true;
        }
    }

    /// The [`StunAgent`] this request is being sent with.
    pub fn agent(&self) -> &StunAgent {
        self.agent
    }

    /// The mutable [`StunAgent`] this request is being sent with.
    pub fn mut_agent(&mut self) -> &mut StunAgent {
        self.agent
    }

    /// Configure timeouts for the STUN transaction.  As specified in RFC 8489, `initial_rto`
    /// should be >= 500ms, `retransmits` has a default value of 7, and `last_retransmit_timeout`
    /// should be 16 * `initial_rto`.
    ///
    /// STUN transactions over TCP will only send a single request and have a timeout of the sum of
    /// the timeouts of a UDP transaction.
    pub fn configure_timeout(
        &mut self,
        initial_rto: Duration,
        retransmits: u32,
        last_retransmit_timeout: Duration,
    ) {
        if let Some(state) = self.agent.mut_request_state(self.transaction_id) {
            match state.transport {
                TransportType::Udp => {
                    state.timeouts_ms = (0..retransmits)
                        .map(|i| (initial_rto * 2u32.pow(i)).as_millis() as u64)
                        .collect::<Vec<_>>();
                    state.last_retransmit_timeout_ms = last_retransmit_timeout.as_millis() as u64;
                }
                TransportType::Tcp => {
                    state.timeouts_ms = vec![];
                    state.last_retransmit_timeout_ms = (last_retransmit_timeout
                        + (0..retransmits)
                            .fold(Duration::ZERO, |acc, i| acc + initial_rto * 2u32.pow(i)))
                    .as_millis() as u64;
                }
            }
        }
    }
}

/// Return value when handling possible STUN data
#[derive(Debug)]
pub enum HandleStunReply<'a> {
    /// The provided data could be parsed as a response to an outstanding request.
    ValidatedStunResponse(Message<'a>),
    /// The provided data could be parsed as an unvalidated response to an outstanding request.
    ///
    /// Care must be taken when handling this message as the credentials used do not match the
    /// agent's remote credentials and could represent an attack.
    UnvalidatedStunResponse(Message<'a>),
    /// The provided data could be parsed as a STUN message.
    IncomingStun(Message<'a>),
    /// Drop this message.
    Drop,
}

/// STUN errors
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StunError {
    /// The operation is already in progress.
    #[error("The operation is already in progress")]
    AlreadyInProgress,
    /// A resource was not found.
    #[error("A required resource could not be found")]
    ResourceNotFound,
    /// An operation timed out without a response.
    #[error("An operation timed out")]
    TimedOut,
    /// Unexpected data was received or an operation is not allowed at this time.
    #[error("Unexpected data was received")]
    ProtocolViolation,
    /// An operation was cancelled.
    #[error("Operation was aborted")]
    Aborted,
    /// A parsing error. The contained error contains more details.
    #[error("{}", .0)]
    ParseError(StunParseError),
    /// A writing error. The contained error contains more details.
    #[error("{}", .0)]
    WriteError(StunWriteError),
}

impl From<StunParseError> for StunError {
    fn from(e: StunParseError) -> Self {
        StunError::ParseError(e)
    }
}

impl From<StunWriteError> for StunError {
    fn from(e: StunWriteError) -> Self {
        StunError::WriteError(e)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use alloc::string::String;
    use tracing::error;

    use super::*;

    #[test]
    fn agent_getters_setters() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();

        assert_eq!(agent.transport(), TransportType::Udp);
        assert_eq!(agent.local_addr(), local_addr);
        assert_eq!(agent.remote_addr(), Some(remote_addr));

        assert_eq!(agent.local_credentials(), None);
        assert_eq!(agent.remote_credentials(), None);

        let local_credentials: MessageIntegrityCredentials =
            ShortTermCredentials::new(String::from("local_password")).into();
        let remote_credentials: MessageIntegrityCredentials =
            ShortTermCredentials::new(String::from("remote_password")).into();
        agent.set_local_credentials(local_credentials.clone());
        agent.set_remote_credentials(remote_credentials.clone());
        assert_eq!(agent.local_credentials(), Some(local_credentials));
        assert_eq!(agent.remote_credentials(), Some(remote_credentials));
    }

    #[test]
    fn request() {
        let _log = crate::tests::test_init_log();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        let transmit = agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();
        let now = Instant::ZERO;
        assert_eq!(transmit.transport, TransportType::Udp);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);
        let request = Message::from_bytes(&transmit.data).unwrap();
        let response = Message::builder_error(&request, MessageWriteVec::new());
        let resp_data = response.finish();
        let response = Message::from_bytes(&resp_data).unwrap();
        let ret = agent.handle_stun(response, remote_addr);
        assert!(matches!(ret, HandleStunReply::ValidatedStunResponse(_)));
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());

        let ret = agent.poll(now);
        assert!(matches!(ret, StunAgentPollRet::WaitUntil(_)));
    }

    #[test]
    fn indication_with_invalid_response() {
        let _log = crate::tests::test_init_log();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let transaction_id = TransactionId::generate();
        let msg = Message::builder(
            MessageType::from_class_method(MessageClass::Indication, BINDING),
            transaction_id,
            MessageWriteVec::new(),
        );
        let transmit = agent
            .send(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();
        assert_eq!(transmit.transport, TransportType::Udp);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);
        let _indication = Message::from_bytes(&transmit.data).unwrap();
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());
        // you should definitely never do this ;). Indications should never get replies.
        let response = Message::builder(
            MessageType::from_class_method(MessageClass::Error, BINDING),
            transaction_id,
            MessageWriteVec::new(),
        );
        let resp_data = response.finish();
        let response = Message::from_bytes(&resp_data).unwrap();
        // response without a request is dropped.
        let ret = agent.handle_stun(response, remote_addr);
        assert!(matches!(ret, HandleStunReply::Drop));
    }

    #[test]
    fn request_with_credentials() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();
        let local_credentials = ShortTermCredentials::new(String::from("local_password"));
        let remote_credentials = ShortTermCredentials::new(String::from("remote_password"));
        agent.set_local_credentials(local_credentials.clone().into());
        agent.set_remote_credentials(remote_credentials.clone().into());

        // unvalidated peer data should be dropped
        assert!(!agent.is_validated_peer(remote_addr));

        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        msg.add_message_integrity(&local_credentials.clone().into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        error!("send");
        let transmit = agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();
        error!("sent");

        let request = Message::from_bytes(&transmit.data).unwrap();

        error!("generate response");
        let mut response = Message::builder_success(&request, MessageWriteVec::new());
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();
        response
            .add_message_integrity(&remote_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        error!("{response:?}");

        let data = response.finish();
        error!("{data:?}");
        let to = transmit.to;
        let response = Message::from_bytes(&data).unwrap();
        error!("{response}");
        let reply = agent.handle_stun(response, to);
        let HandleStunReply::ValidatedStunResponse(response) = reply else {
            unreachable!();
        };

        assert_eq!(response.transaction_id(), transaction_id);
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());
        assert!(agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn request_unanswered() {
        let _log = crate::tests::test_init_log();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();
        let mut now = Instant::ZERO;
        loop {
            let _ = agent.poll_transmit(now);
            match agent.poll(now) {
                StunAgentPollRet::WaitUntil(new_now) => {
                    now = new_now;
                }
                StunAgentPollRet::TransactionTimedOut(_) => break,
                _ => unreachable!(),
            }
        }
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());

        // unvalidated peer data should be dropped
        assert!(!agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn request_custom_timeout() {
        let _log = crate::tests::test_init_log();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        let mut now = Instant::ZERO;
        agent.send_request(msg.finish(), remote_addr, now).unwrap();
        let mut transaction = agent.mut_request_transaction(transaction_id).unwrap();
        transaction.configure_timeout(Duration::from_secs(1), 2, Duration::from_secs(10));
        let StunAgentPollRet::WaitUntil(wait) = agent.poll(now) else {
            unreachable!();
        };
        assert_eq!(wait - now, Duration::from_secs(1));
        now = wait;
        // a poll with the same instant should not busy loop
        let StunAgentPollRet::WaitUntil(wait) = agent.poll(now) else {
            unreachable!();
        };
        assert_eq!(wait, now);
        let Some(_) = agent.poll_transmit(now) else {
            unreachable!();
        };
        let StunAgentPollRet::WaitUntil(wait) = agent.poll(now) else {
            unreachable!();
        };
        assert_eq!(wait - now, Duration::from_secs(2));
        now = wait;
        let Some(_) = agent.poll_transmit(now) else {
            unreachable!();
        };
        let StunAgentPollRet::WaitUntil(wait) = agent.poll(now) else {
            unreachable!();
        };
        assert_eq!(wait - now, Duration::from_secs(10));
        now = wait;
        let StunAgentPollRet::TransactionTimedOut(timed_out) = agent.poll(now) else {
            unreachable!();
        };
        assert_eq!(timed_out, transaction_id);

        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());

        // unvalidated peer data should be dropped
        assert!(!agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn request_no_retransmit() {
        let _log = crate::tests::test_init_log();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        let mut now = Instant::ZERO;
        agent.send_request(msg.finish(), remote_addr, now).unwrap();
        let mut transaction = agent.mut_request_transaction(transaction_id).unwrap();
        transaction.configure_timeout(Duration::from_secs(1), 0, Duration::from_secs(10));
        let StunAgentPollRet::WaitUntil(wait) = agent.poll(now) else {
            unreachable!();
        };
        assert_eq!(wait - now, Duration::from_secs(10));
        now = wait;
        let StunAgentPollRet::TransactionTimedOut(timed_out) = agent.poll(now) else {
            unreachable!();
        };
        assert_eq!(timed_out, transaction_id);

        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());

        // unvalidated peer data should be dropped
        assert!(!agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn request_tcp_custom_timeout() {
        let _log = crate::tests::test_init_log();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        let mut now = Instant::ZERO;
        agent.send_request(msg.finish(), remote_addr, now).unwrap();
        let mut transaction = agent.mut_request_transaction(transaction_id).unwrap();
        transaction.configure_timeout(Duration::from_secs(1), 3, Duration::from_secs(3));
        let StunAgentPollRet::WaitUntil(wait) = agent.poll(now) else {
            unreachable!();
        };
        assert_eq!(wait - now, Duration::from_secs(1 + 2 + 4 + 3));
        now = wait;
        let StunAgentPollRet::TransactionTimedOut(timed_out) = agent.poll(now) else {
            unreachable!();
        };
        assert_eq!(timed_out, transaction_id);

        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());

        // unvalidated peer data should be dropped
        assert!(!agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn request_without_credentials() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        // unvalidated peer data should be dropped
        assert!(!agent.is_validated_peer(remote_addr));

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        let transmit = agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::builder_success(&request, MessageWriteVec::new());
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();

        let data = response.finish();
        let to = transmit.to;
        trace!("data: {data:?}");
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);

        assert!(matches!(reply, HandleStunReply::ValidatedStunResponse(_)));
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());
        assert!(agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn response_without_credentials() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();
        let local_credentials = ShortTermCredentials::new(String::from("local_password"));
        let remote_credentials = ShortTermCredentials::new(String::from("remote_password"));
        agent.set_local_credentials(local_credentials.clone().into());
        agent.set_remote_credentials(remote_credentials.clone().into());

        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        msg.add_message_integrity(&local_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        let transmit = agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::builder_success(&request, MessageWriteVec::new());
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();

        let data = response.finish();
        let to = transmit.to;
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);
        // reply is ignored as it does not have credentials
        assert!(matches!(reply, HandleStunReply::UnvalidatedStunResponse(_)));
        assert!(agent.request_transaction(transaction_id).is_some());
        assert!(agent.mut_request_transaction(transaction_id).is_some());

        // removing the request, causes the transaction to be unretrievable
        assert!(agent.remove_outstanding_request(transaction_id));
        assert!(!agent.remove_outstanding_request(transaction_id));

        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());

        // unvalidated peer data should be dropped
        assert!(!agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn agent_response_without_credentials() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();
        let local_credentials = ShortTermCredentials::new(String::from("local_password"));
        agent.set_local_credentials(local_credentials.clone().into());

        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        msg.add_message_integrity(&local_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        let transmit = agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::builder_success(&request, MessageWriteVec::new());
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();

        let data = response.finish();
        let to = transmit.to;
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);
        // reply is ignored as it does not have credentials
        assert!(matches!(reply, HandleStunReply::UnvalidatedStunResponse(_)));
        assert!(agent.request_transaction(transaction_id).is_some());
        assert!(agent.mut_request_transaction(transaction_id).is_some());

        // removing the request, causes the transaction to be unretrievable
        assert!(agent.remove_outstanding_request(transaction_id));
        assert!(!agent.remove_outstanding_request(transaction_id));

        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());

        // unvalidated peer data should be dropped
        assert!(!agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn response_with_incorrect_credentials() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();
        let local_credentials = ShortTermCredentials::new(String::from("local_password"));
        let remote_credentials = ShortTermCredentials::new(String::from("remote_password"));
        agent.set_local_credentials(local_credentials.clone().into());
        agent.set_remote_credentials(remote_credentials.into());

        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        msg.add_message_integrity(&local_credentials.clone().into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        let transmit = agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();
        let data = transmit.data;

        let request = Message::from_bytes(&data).unwrap();

        let mut response = Message::builder_success(&request, MessageWriteVec::new());
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();
        // wrong credentials, should be `remote_credentials`
        response
            .add_message_integrity(&local_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();

        let data = response.finish();
        let to = transmit.to;
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);
        // reply is ignored as it does not have credentials
        assert!(matches!(reply, HandleStunReply::UnvalidatedStunResponse(_)));
        assert!(agent.remove_outstanding_request(transaction_id));
        assert!(!agent.remove_outstanding_request(transaction_id));

        // unvalidated peer data should be dropped
        assert!(!agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn duplicate_response_ignored() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();
        assert!(!agent.is_validated_peer(remote_addr));

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transmit = agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();
        let data = transmit.data;

        let request = Message::from_bytes(&data).unwrap();

        let mut response = Message::builder_success(&request, MessageWriteVec::new());
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();

        let data = response.finish();
        let to = transmit.to;
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);
        assert!(matches!(reply, HandleStunReply::ValidatedStunResponse(_)));

        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);
        assert!(matches!(reply, HandleStunReply::Drop));
    }

    #[test]
    fn request_cancel() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        let _transmit = agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();

        let mut request = agent.mut_request_transaction(transaction_id).unwrap();
        assert_eq!(request.agent().local_addr(), local_addr);
        assert_eq!(request.mut_agent().local_addr(), local_addr);
        assert_eq!(request.peer_address(), remote_addr);
        request.cancel();

        let ret = agent.poll(Instant::ZERO);
        let StunAgentPollRet::TransactionCancelled(_request) = ret else {
            unreachable!();
        };
        assert_eq!(transaction_id, transaction_id);
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());
        assert!(!agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn request_cancel_send() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        let _transmit = agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();

        let mut request = agent.mut_request_transaction(transaction_id).unwrap();
        assert_eq!(request.agent().local_addr(), local_addr);
        assert_eq!(request.mut_agent().local_addr(), local_addr);
        assert_eq!(request.peer_address(), remote_addr);
        request.cancel_retransmissions();

        let mut now = Instant::ZERO;
        let start = now;
        loop {
            match agent.poll(now) {
                StunAgentPollRet::WaitUntil(new_now) => {
                    assert_ne!(new_now, now);
                    now = new_now;
                }
                StunAgentPollRet::TransactionCancelled(_) => break,
                _ => unreachable!(),
            }
            let _ = agent.poll_transmit(now);
        }
        assert!(now - start > Duration::from_secs(20));
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());
        assert!(!agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn request_duplicate() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        let msg = msg.finish();
        let transmit = agent
            .send_request(msg.clone(), remote_addr, Instant::ZERO)
            .unwrap();
        let to = transmit.to;
        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::builder_success(&request, MessageWriteVec::new());
        let xor_addr = XorMappedAddress::new(transmit.from, transaction_id);
        response.add_attribute(&xor_addr).unwrap();

        assert!(matches!(
            agent.send_request(msg, remote_addr, Instant::ZERO),
            Err(StunError::AlreadyInProgress)
        ));

        // the original transaction should still exist
        let request = agent.request_transaction(transaction_id).unwrap();
        assert_eq!(request.peer_address(), remote_addr);

        let data = response.finish();
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);

        let HandleStunReply::ValidatedStunResponse(response) = reply else {
            unreachable!();
        };
        assert_eq!(response.transaction_id(), transaction_id);
        assert!(agent.is_validated_peer(to));
    }

    #[test]
    fn incoming_request() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        let data = msg.finish();
        let stun = Message::from_bytes(&data).unwrap();
        error!("{stun:?}");
        let HandleStunReply::IncomingStun(request) = agent.handle_stun(stun, remote_addr) else {
            unreachable!()
        };
        assert_eq!(transaction_id, request.transaction_id());
        assert!(agent.is_validated_peer(remote_addr));
    }

    #[test]
    fn tcp_request() {
        let _log = crate::tests::test_init_log();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let transaction_id = msg.transaction_id();
        let transmit = agent
            .send_request(msg.finish(), remote_addr, Instant::ZERO)
            .unwrap();
        assert_eq!(transmit.transport, TransportType::Tcp);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);

        let request = Message::from_bytes(&transmit.data).unwrap();
        assert_eq!(request.transaction_id(), transaction_id);
    }

    #[test]
    fn transmit_into_owned() {
        let data = [0x10, 0x20];
        let transport = TransportType::Udp;
        let from = "127.0.0.1:1000".parse().unwrap();
        let to = "127.0.0.1:2000".parse().unwrap();
        let transmit = Transmit::new(Data::from(data.as_ref()), TransportType::Udp, from, to);
        let owned = transmit.into_owned();
        assert_eq!(owned.data.as_ref(), data.as_ref());
        assert_eq!(owned.transport, transport);
        assert_eq!(owned.from, from);
        assert_eq!(owned.to, to);
        error!("{owned}");
    }
}
