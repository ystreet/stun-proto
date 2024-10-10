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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use std::time::{Duration, Instant};

use std::collections::{HashMap, HashSet};

use byteorder::{BigEndian, ByteOrder};

use stun_types::attribute::*;
use stun_types::data::Data;
use stun_types::message::*;

use crate::DebugWrapper;

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
    validated_peers: HashSet<SocketAddr>,
    outstanding_requests: HashMap<TransactionId, StunRequestState>,
    local_credentials: Option<MessageIntegrityCredentials>,
    remote_credentials: Option<MessageIntegrityCredentials>,
}

/// Builder struct for a [`StunAgent`]
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
    pub fn send_data<'a>(&self, bytes: &'a [u8], to: SocketAddr) -> Transmit<'a> {
        send_data(self.transport, bytes, self.local_addr, to)
    }

    /// Perform any operations needed to be able to send a [`Message`] to a peer.
    ///
    /// If a request message is successfully sent, then [`StunAgent::poll`] needs to be called.
    pub fn send(
        &mut self,
        msg: MessageBuilder<'_>,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<'_>, StunError> {
        if msg.has_class(MessageClass::Request) {
            if self
                .outstanding_requests
                .contains_key(&msg.transaction_id())
            {
                return Err(StunError::AlreadyInProgress);
            }
            let transaction_id = msg.transaction_id();
            let mut state = StunRequestState::new(msg, self.transport, self.local_addr, to);
            let StunRequestPollRet::SendData(transmit) = state.poll(now) else {
                return Err(StunError::ProtocolViolation);
            };
            let transmit = transmit.into_owned();
            self.outstanding_requests.insert(transaction_id, state);
            return Ok(transmit);
        }
        let data = msg.build();
        Ok(self.send_data(&data, to).into_owned())
    }

    /// Returns whether this agent has received or send a STUN message to this peer. Failure may
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
        if self.validated_peers.get(&addr).is_none() {
            debug!("validated peer {:?}", addr);
            self.validated_peers.insert(addr);
        }
    }

    /// Provide data received on a socket from a peer for handling by the [`StunAgent`].
    /// The returned value indicates what the caller must do with the data.
    ///
    /// If this function returns [`HandleStunReply::StunResponse`], then this agent needs to be
    /// `poll()`ed again.
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
                            HandleStunReply::StunResponse(msg)
                        }
                        Err(e) => {
                            debug!("message failed integrity check: {:?}", e);
                            self.outstanding_requests
                                .insert(msg.transaction_id(), request);
                            HandleStunReply::Drop
                        }
                    }
                } else {
                    // XXX: may need to return this as 'Unvalididated'.
                    debug!("no remote credentials, ignoring");
                    self.outstanding_requests
                        .insert(msg.transaction_id(), request);
                    HandleStunReply::Drop
                }
            } else {
                // original message didn't have integrity, reply doesn't need to either
                self.validated_peer(from);
                HandleStunReply::StunResponse(msg)
            }
        } else {
            self.validated_peer(from);
            HandleStunReply::IncomingStun(msg)
        }
    }

    #[tracing::instrument(skip(self, transaction_id),
        fields(transaction_id = %transaction_id))]
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

    /// Retrieve a reference to an outstanding STUN request. Outstanding requests are kept until
    /// either `handle_incoming_data` receives the associated response, or `poll()` returns
    /// [`StunAgentPollRet::TransactionCancelled`] or a [`StunAgentPollRet::TransactionTimedOut`]
    /// for the request.
    pub fn request_transaction(&self, transaction_id: TransactionId) -> Option<StunRequest> {
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
    /// until either `handle_incoming_data` receives the associated response, or `poll()` returns
    /// [`StunAgentPollRet::TransactionCancelled`] or a [`StunAgentPollRet::TransactionTimedOut`]
    /// for the request.
    pub fn mut_request_transaction(
        &mut self,
        transaction_id: TransactionId,
    ) -> Option<StunRequestMut> {
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
    #[tracing::instrument(
        name = "stun_request_poll"
        level = "info",
        ret,
        skip(self),
    )]
    pub fn poll<'a>(&mut self, now: Instant) -> StunAgentPollRet<'a> {
        let mut lowest_wait = now + Duration::from_secs(3600);
        let mut timeout = None;
        let mut cancelled = None;
        for request in self.outstanding_requests.values_mut() {
            let transaction_id = request.transaction_id;
            match request.poll(now) {
                StunRequestPollRet::Cancelled => {
                    cancelled = Some(transaction_id);
                    break;
                }
                StunRequestPollRet::SendData(transmit) => {
                    return StunAgentPollRet::SendData(transmit.into_owned())
                }
                StunRequestPollRet::WaitUntil(wait_until) => {
                    if wait_until < lowest_wait {
                        lowest_wait = wait_until;
                    }
                }
                StunRequestPollRet::TimedOut => {
                    timeout = Some(transaction_id);
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
}

/// Return value for [`StunAgent::poll`]
#[derive(Debug)]
pub enum StunAgentPollRet<'a> {
    /// An oustanding transaction timed out and has been removed from the agent.
    TransactionTimedOut(TransactionId),
    /// An oustanding transaction was cancelled and has been removed from the agent.
    TransactionCancelled(TransactionId),
    /// Send data using the specified 5-tuple
    SendData(Transmit<'a>),
    /// Wait until the specified time has passed
    WaitUntil(Instant),
}

fn send_data(transport: TransportType, bytes: &[u8], from: SocketAddr, to: SocketAddr) -> Transmit {
    Transmit::new(bytes, transport, from, to)
}

/// A buffer object for handling STUN data received over a TCP connection that requires framing as
/// specified in RFC 4571.  This framing is required for ICE usage of TCP candidates.
#[derive(Debug)]
pub struct TcpBuffer {
    buf: DebugWrapper<Vec<u8>>,
}

impl TcpBuffer {
    /// Construct a new [`TcpBuffer`]
    pub fn new() -> Self {
        Self {
            buf: DebugWrapper::wrap(vec![], "..."),
        }
    }

    /// Push a chunk of received data into the buffer.
    pub fn push_data(&mut self, data: &[u8]) {
        self.buf.extend(data);
    }

    /// Pull the next chunk of data from the buffer.  If no buffer is available, then None is
    /// returned.
    pub fn pull_data(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 2 {
            trace!(
                "running buffer is currently too small ({} bytes) to provide data",
                self.buf.len()
            );
            return None;
        }

        let data_length = (BigEndian::read_u16(&self.buf[..2]) as usize) + 2;
        if self.buf.len() < data_length {
            trace!(
                "not enough data, buf length {} data specifies length {}",
                self.buf.len(),
                data_length
            );
            return None;
        }

        let bytes = self.take(data_length);
        trace!("return {} bytes", data_length - 2);
        Some(bytes[2..].to_vec())
    }

    fn take(&mut self, offset: usize) -> Vec<u8> {
        if offset > self.buf.len() {
            return vec![];
        }
        let (data, rest) = self.buf.split_at(offset);
        let data = data.to_vec();
        self.buf = DebugWrapper::wrap(rest.to_vec(), "...");
        data
    }
}

impl Default for TcpBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// A piece of data that needs to, or has been transmitted
#[derive(Debug)]
pub struct Transmit<'a> {
    /// The data blob
    pub data: Data<'a>,
    /// The transport for the transmission
    pub transport: TransportType,
    /// The source address of the transmission
    pub from: SocketAddr,
    /// The destination address of the transmission
    pub to: SocketAddr,
}

impl<'a> Transmit<'a> {
    /// Construct a new [`Transmit`] with the specifid data and 5-tuple.
    pub fn new(
        data: impl Into<Data<'a>>,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Self {
        Self {
            data: data.into(),
            transport,
            from,
            to,
        }
    }

    /// Construct a new [`Transmit`] with the specifid 5-tuple and data converted to owned.
    pub fn new_owned(
        data: impl Into<Data<'a>>,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Transmit<'static> {
        Transmit {
            data: data.into().into_owned(),
            transport,
            from,
            to,
        }
    }

    /// Consume this [`Transmit`] and produce and owned version.
    pub fn into_owned<'b>(self) -> Transmit<'b> {
        Transmit {
            data: self.data.into_owned(),
            transport: self.transport,
            from: self.from,
            to: self.to,
        }
    }

    /// The bytes to transmit
    pub fn data(&self) -> &[u8] {
        match &self.data {
            Data::Owned(owned) => owned,
            Data::Borrowed(borrowed) => borrowed,
        }
    }
}

/// Return value for [`StunRequest::poll`]
#[derive(Debug)]
enum StunRequestPollRet<'a> {
    /// Wait until the specified time has passed
    WaitUntil(Instant),
    /// The request has been cancelled and will not make further progress
    Cancelled,
    /// Send data using the specified 5-tuple
    SendData(Transmit<'a>),
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
    recv_cancelled: bool,
    send_cancelled: bool,
    timeout_i: usize,
    last_send_time: Option<Instant>,
}

impl StunRequestState {
    fn new(
        request: MessageBuilder<'_>,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Self {
        let data = request.build();
        let timeouts_ms = if transport == TransportType::Tcp {
            vec![39500]
        } else {
            vec![500, 1000, 2000, 4000, 8000, 16000]
        };
        Self {
            transaction_id: request.transaction_id(),
            bytes: data,
            transport,
            from,
            to,
            request_had_credentials: request.has_attribute(MessageIntegrity::TYPE)
                || request.has_attribute(MessageIntegritySha256::TYPE),
            timeouts_ms,
            timeout_i: 0,
            recv_cancelled: false,
            send_cancelled: false,
            last_send_time: None,
        }
    }

    #[tracing::instrument(
        name = "stun_request_poll"
        level = "info",
        ret,
        skip(self),
        fields(transaction_id = %self.transaction_id),
    )]
    fn poll(&mut self, now: Instant) -> StunRequestPollRet {
        if self.recv_cancelled {
            return StunRequestPollRet::Cancelled;
        }
        // TODO: account for TCP connect in timeout
        if let Some(last_send) = self.last_send_time {
            if self.timeout_i >= self.timeouts_ms.len() {
                return StunRequestPollRet::TimedOut;
            }
            let next_send = last_send + Duration::from_millis(self.timeouts_ms[self.timeout_i]);
            if next_send > now {
                return StunRequestPollRet::WaitUntil(next_send);
            }
            self.timeout_i += 1;
        }
        if self.send_cancelled {
            // this calcelaltion may need a different value
            return StunRequestPollRet::Cancelled;
        }
        self.last_send_time = Some(now);
        StunRequestPollRet::SendData(
            send_data(self.transport, &self.bytes, self.from, self.to).into_owned(),
        )
    }
}

/// A STUN Request
#[derive(Debug, Clone)]
pub struct StunRequest<'a> {
    agent: &'a StunAgent,
    transaction_id: TransactionId,
}

impl<'a> StunRequest<'a> {
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

impl<'a> StunRequestMut<'a> {
    /// The remote address the request is sent to
    pub fn peer_address(&self) -> SocketAddr {
        let state = self.agent.request_state(self.transaction_id).unwrap();
        state.to
    }

    /// Do not retransmit further
    pub fn cancel_retransmissions(&mut self) {
        if let Some(state) = self.agent.mut_request_state(self.transaction_id) {
            state.send_cancelled = true;
        }
    }

    /// Do not wait for any kind of response
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
}

/// Return value when handling possible STUN data
#[derive(Debug)]
pub enum HandleStunReply<'a> {
    /// The provided data could be parsed as a response to an outstanding request
    StunResponse(Message<'a>),
    /// The provided data could be parsed as a STUN message
    IncomingStun(Message<'a>),
    /// Drop this message.
    Drop,
}

/// STUN errors
#[derive(Debug, thiserror::Error)]
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
        let msg = Message::builder_request(BINDING);
        let transaction_id = msg.transaction_id();
        let transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();
        let now = Instant::now();
        assert_eq!(transmit.transport, TransportType::Udp);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);
        let request = Message::from_bytes(&transmit.data).unwrap();
        let response = Message::builder_error(&request);
        let resp_data = response.build();
        let response = Message::from_bytes(&resp_data).unwrap();
        let ret = agent.handle_stun(response, remote_addr);
        assert!(matches!(ret, HandleStunReply::StunResponse(_)));
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
        );
        let transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();
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
        );
        let resp_data = response.build();
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

        let mut msg = Message::builder_request(BINDING);
        let transaction_id = msg.transaction_id();
        msg.add_message_integrity(&local_credentials.clone().into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        println!("send");
        let transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();
        println!("sent");

        let request = Message::from_bytes(&transmit.data).unwrap();

        println!("generate response");
        let mut response = Message::builder_success(&request);
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();
        response
            .add_message_integrity(&remote_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        println!("{response:?}");

        let data = response.build();
        println!("{data:?}");
        let to = transmit.to;
        let response = Message::from_bytes(&data).unwrap();
        println!("{response}");
        let reply = agent.handle_stun(response, to);
        let HandleStunReply::StunResponse(response) = reply else {
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
        let msg = Message::builder_request(BINDING);
        let transaction_id = msg.transaction_id();
        agent.send(msg, remote_addr, Instant::now()).unwrap();
        let mut now = Instant::now();
        loop {
            match agent.poll(now) {
                StunAgentPollRet::WaitUntil(new_now) => {
                    now = new_now;
                }
                StunAgentPollRet::SendData(_) => (),
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
    fn request_without_credentials() {
        let _log = crate::tests::test_init_log();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        // unvalidated peer data should be dropped
        assert!(!agent.is_validated_peer(remote_addr));

        let msg = Message::builder_request(BINDING);
        let transaction_id = msg.transaction_id();
        let transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::builder_success(&request);
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();

        let data = response.build();
        let to = transmit.to;
        trace!("data: {data:?}");
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);

        assert!(matches!(reply, HandleStunReply::StunResponse(_)));
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

        let mut msg = Message::builder_request(BINDING);
        let transaction_id = msg.transaction_id();
        msg.add_message_integrity(&local_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        let transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::builder_success(&request);
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();

        let data = response.build();
        let to = transmit.to;
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);
        // reply is ignored as it does not have credentials
        assert!(matches!(reply, HandleStunReply::Drop));
        assert!(agent.request_transaction(transaction_id).is_some());
        assert!(agent.mut_request_transaction(transaction_id).is_some());

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

        let mut msg = Message::builder_request(BINDING);
        let transaction_id = msg.transaction_id();
        msg.add_message_integrity(&local_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        let transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::builder_success(&request);
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();

        let data = response.build();
        let to = transmit.to;
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);
        // reply is ignored as it does not have credentials
        assert!(matches!(reply, HandleStunReply::Drop));
        assert!(agent.request_transaction(transaction_id).is_some());
        assert!(agent.mut_request_transaction(transaction_id).is_some());

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

        let mut msg = Message::builder_request(BINDING);
        msg.add_message_integrity(&local_credentials.clone().into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        let transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::builder_success(&request);
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();
        // wrong credentials, should be `remote_credentials`
        response
            .add_message_integrity(&local_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();

        let data = response.build();
        let to = transmit.to;
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);
        // reply is ignored as it does not have credentials
        assert!(matches!(reply, HandleStunReply::Drop));

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

        let msg = Message::builder_request(BINDING);
        let transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::builder_success(&request);
        let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
        response.add_attribute(&xor_addr).unwrap();

        let data = response.build();
        let to = transmit.to;
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);
        assert!(matches!(reply, HandleStunReply::StunResponse(_)));

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

        let msg = Message::builder_request(BINDING);
        let transaction_id = msg.transaction_id();
        let _transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();

        let mut request = agent.mut_request_transaction(transaction_id).unwrap();
        assert_eq!(request.agent().local_addr(), local_addr);
        assert_eq!(request.mut_agent().local_addr(), local_addr);
        assert_eq!(request.peer_address(), remote_addr);
        request.cancel();

        let ret = agent.poll(Instant::now());
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

        let msg = Message::builder_request(BINDING);
        let transaction_id = msg.transaction_id();
        let _transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();

        let mut request = agent.mut_request_transaction(transaction_id).unwrap();
        assert_eq!(request.agent().local_addr(), local_addr);
        assert_eq!(request.mut_agent().local_addr(), local_addr);
        assert_eq!(request.peer_address(), remote_addr);
        request.cancel_retransmissions();

        let mut now = Instant::now();
        loop {
            match agent.poll(now) {
                StunAgentPollRet::WaitUntil(new_now) => {
                    now = new_now;
                }
                StunAgentPollRet::TransactionCancelled(_) => break,
                _ => unreachable!(),
            }
        }
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

        let msg = Message::builder_request(BINDING);
        let transaction_id = msg.transaction_id();
        let transmit = agent
            .send(msg.clone(), remote_addr, Instant::now())
            .unwrap();
        let to = transmit.to;
        let request = Message::from_bytes(transmit.data()).unwrap();

        let mut response = Message::builder_success(&request);
        let xor_addr = XorMappedAddress::new(transmit.from, transaction_id);
        response.add_attribute(&xor_addr).unwrap();

        assert!(matches!(
            agent.send(msg, remote_addr, Instant::now()),
            Err(StunError::AlreadyInProgress)
        ));

        // the original transaction should still exist
        let request = agent.request_transaction(transaction_id).unwrap();
        assert_eq!(request.peer_address(), remote_addr);

        let data = response.build();
        let response = Message::from_bytes(&data).unwrap();
        let reply = agent.handle_stun(response, to);

        let HandleStunReply::StunResponse(response) = reply else {
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

        let msg = Message::builder_request(BINDING);
        let data = msg.build();
        let stun = Message::from_bytes(&data).unwrap();
        println!("{stun:?}");
        let HandleStunReply::IncomingStun(request) = agent.handle_stun(stun, remote_addr) else {
            unreachable!()
        };
        assert_eq!(msg.transaction_id(), request.transaction_id());
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

        let msg = Message::builder_request(BINDING);
        let transaction_id = msg.transaction_id();
        let transmit = agent.send(msg, remote_addr, Instant::now()).unwrap();
        assert_eq!(transmit.transport, TransportType::Tcp);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);

        let request = Message::from_bytes(&transmit.data).unwrap();
        assert_eq!(request.transaction_id(), transaction_id);
    }

    #[test]
    fn tcp_buffer_split_recv() {
        let _log = crate::tests::test_init_log();

        let mut tcp_buffer = TcpBuffer::default();

        let mut len = [0; 2];
        let data = [0, 1, 2, 4, 3];
        BigEndian::write_u16(&mut len, data.len() as u16);

        tcp_buffer.push_data(&len);
        assert!(tcp_buffer.pull_data().is_none());
        tcp_buffer.push_data(&data);
        assert_eq!(tcp_buffer.pull_data().unwrap(), &data);
    }
}
