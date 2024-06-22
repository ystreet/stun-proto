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
    tcp_buffer: Option<TcpBuffer>,
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
        let tcp_buffer = match self.transport {
            TransportType::Udp => None,
            TransportType::Tcp => Some(TcpBuffer::new()),
        };
        StunAgent {
            id,
            transport: self.transport,
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            validated_peers: Default::default(),
            outstanding_requests: Default::default(),
            local_credentials: None,
            remote_credentials: None,
            tcp_buffer,
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

    /// Perform any operations needed to be able to send a [`Message`] to a peer
    pub fn send(&mut self, msg: Message, to: SocketAddr) -> Result<Transmit<'_>, StunError> {
        let data = msg.to_bytes();
        if msg.has_class(MessageClass::Request) {
            if self
                .outstanding_requests
                .contains_key(&msg.transaction_id())
            {
                return Err(StunError::AlreadyInProgress);
            }
            let transaction_id = msg.transaction_id();
            let mut state = StunRequestState::new(msg, self.transport, self.local_addr, to);
            let StunRequestPollRet::SendData(transmit) = state.poll(Instant::now()) else {
                return Err(StunError::ProtocolViolation);
            };
            let transmit = transmit.into_owned();
            self.outstanding_requests.insert(transaction_id, state);
            return Ok(transmit);
        }
        Ok(self.send_data(&data, to).into_owned())
    }

    fn parse_chunk(
        &mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<Option<HandleStunReply>, StunError> {
        match Message::from_bytes(data) {
            Ok(stun_msg) => {
                debug!("received stun {}", stun_msg);
                self.handle_stun(stun_msg, data, from)
            }
            Err(_) => {
                let peer_validated = { self.validated_peers.contains(&from) };
                if peer_validated {
                    Ok(Some(HandleStunReply::Data(data.to_vec())))
                } else if self.transport == TransportType::Tcp {
                    // close the tcp channel
                    warn!("stun message not the first message sent over TCP channel, closing");
                    Err(StunError::ProtocolViolation)
                } else {
                    trace!("dropping unvalidated data from peer");
                    Ok(None)
                }
            }
        }
    }

    /// Provide data received on a socket from a peer for handling by the [`StunAgent`].
    /// The returned value indicates what the caller must do with the data.
    ///
    /// After this call, any outstanding [`StunRequest`] may need to be `poll()`ed again.
    #[tracing::instrument(
        name = "stun_incoming_data"
        level = "info",
        skip(self, data),
        fields(
            stun_id = self.id,
            to = ?self.local_addr()
        )
    )]
    pub fn handle_incoming_data(
        &mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<Vec<HandleStunReply>, StunError> {
        match self.transport {
            TransportType::Udp => {
                if let Some(reply) = self.parse_chunk(data, from)? {
                    Ok(vec![reply])
                } else {
                    Ok(vec![])
                }
            }
            TransportType::Tcp => {
                let mut ret = vec![];
                let tcp = self.tcp_buffer.as_mut().unwrap();
                tcp.push_data(data);
                let mut datas = vec![];
                while let Some(data) = tcp.pull_data() {
                    datas.push(data);
                }
                for data in datas {
                    if let Some(reply) = self.parse_chunk(&data, from)? {
                        ret.push(reply);
                    }
                }
                Ok(ret)
            }
        }
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

    #[tracing::instrument(
        name = "stun_handle_message"
        skip(self, msg, orig_data, from),
        fields(
            transaction_id = %msg.transaction_id(),
        )
    )]
    fn handle_stun(
        &mut self,
        msg: Message,
        orig_data: &[u8],
        from: SocketAddr,
    ) -> Result<Option<HandleStunReply>, StunError> {
        if msg.is_response() {
            let Some(request) = self.take_outstanding_request(&msg.transaction_id()) else {
                trace!("original request disappeared -> ignoring response");
                return Ok(None);
            };
            // only validate response if the original request had credentials
            if request.msg.has_attribute(MessageIntegrity::TYPE) {
                if let Some(remote_creds) = &self.remote_credentials {
                    match msg.validate_integrity(orig_data, remote_creds) {
                        Ok(_) => {
                            self.validated_peer(from);
                            Ok(Some(HandleStunReply::StunResponse(request.msg, msg)))
                        }
                        Err(e) => {
                            debug!("message failed integrity check: {:?}", e);
                            self.outstanding_requests
                                .insert(msg.transaction_id(), request);
                            Ok(None)
                        }
                    }
                } else {
                    debug!("no remote credentials, ignoring");
                    self.outstanding_requests
                        .insert(msg.transaction_id(), request);
                    Ok(None)
                }
            } else {
                // original message didn't have integrity, reply doesn't need to either
                self.validated_peer(from);
                Ok(Some(HandleStunReply::StunResponse(request.msg, msg)))
            }
        } else {
            self.validated_peer(from);
            Ok(Some(HandleStunReply::IncomingStun(msg)))
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

    /// Retrieve a reference to an outstanding STUN request
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

    /// Retrieve a mutable reference to an outstanding STUN request
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

    /// Poll the agent for making further progress on any outstanding requests.  The returned value
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
            let transaction_id = request.msg.transaction_id();
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
            if let Some(state) = self.outstanding_requests.remove(&transaction) {
                return StunAgentPollRet::TransactionTimedOut(state.msg);
            }
        }
        if let Some(transaction) = cancelled {
            if let Some(state) = self.outstanding_requests.remove(&transaction) {
                return StunAgentPollRet::TransactionCancelled(state.msg);
            }
        }
        StunAgentPollRet::WaitUntil(lowest_wait)
    }
}

/// Return value for [`StunAgent::poll`]
#[derive(Debug)]
pub enum StunAgentPollRet<'a> {
    /// An oustanding transaction timed out.
    TransactionTimedOut(Message),
    /// An oustanding transaction was cancelled.
    TransactionCancelled(Message),
    /// Send data using the specified 5-tuple
    SendData(Transmit<'a>),
    /// Wait until the specified time has passed
    WaitUntil(Instant),
}

fn send_data(
    transport: TransportType,
    bytes: &[u8],
    from: SocketAddr,
    to: SocketAddr,
) -> Transmit<'static> {
    match transport {
        TransportType::Udp => Transmit::new(bytes, transport, from, to),
        TransportType::Tcp => {
            let mut data = Vec::with_capacity(bytes.len() + 2);
            data.resize(2, 0);
            BigEndian::write_u16(&mut data, bytes.len() as u16);
            data.extend(bytes);
            Transmit::new_owned(data.into_boxed_slice(), transport, from, to)
        }
    }
    .into_owned()
}

#[derive(Debug)]
struct TcpBuffer {
    buf: DebugWrapper<Vec<u8>>,
}

impl TcpBuffer {
    fn new() -> Self {
        Self {
            buf: DebugWrapper::wrap(vec![], "..."),
        }
    }

    fn push_data(&mut self, data: &[u8]) {
        self.buf.extend(data);
    }

    fn pull_data(&mut self) -> Option<Vec<u8>> {
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

/// A slice of data
#[derive(Debug)]
#[repr(transparent)]
pub struct DataSlice<'a>(&'a [u8]);

impl<'a> DataSlice<'a> {
    pub fn take(self) -> &'a [u8] {
        self.0
    }

    pub fn to_owned(&self) -> DataOwned {
        DataOwned(self.0.into())
    }
}

impl<'a> std::ops::Deref for DataSlice<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> From<DataSlice<'a>> for &'a [u8] {
    fn from(value: DataSlice<'a>) -> Self {
        value.0
    }
}

impl<'a> From<&'a [u8]> for DataSlice<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}

/// An owned piece of data
#[derive(Debug)]
#[repr(transparent)]
pub struct DataOwned(Box<[u8]>);

impl DataOwned {
    pub fn take(self) -> Box<[u8]> {
        self.0
    }
}

impl std::ops::Deref for DataOwned {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<DataOwned> for Box<[u8]> {
    fn from(value: DataOwned) -> Self {
        value.0
    }
}

impl From<Box<[u8]>> for DataOwned {
    fn from(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

/// An owned or borrowed piece of data
#[derive(Debug)]
pub enum Data<'a> {
    Borrowed(DataSlice<'a>),
    Owned(DataOwned),
}

impl<'a> std::ops::Deref for Data<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(data) => data.0,
            Self::Owned(data) => &data.0,
        }
    }
}

impl<'a> Data<'a> {
    fn into_owned<'b>(self) -> Data<'b> {
        match self {
            Self::Borrowed(data) => Data::Owned(data.to_owned()),
            Self::Owned(data) => Data::Owned(data),
        }
    }
}

impl<'a> From<&'a [u8]> for Data<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Borrowed(value.into())
    }
}

impl<'a> From<Box<[u8]>> for Data<'a> {
    fn from(value: Box<[u8]>) -> Self {
        Self::Owned(value.into())
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
    msg: Message,
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
    fn new(request: Message, transport: TransportType, from: SocketAddr, to: SocketAddr) -> Self {
        let data = request.to_bytes();
        let timeouts_ms = if transport == TransportType::Tcp {
            vec![39500]
        } else {
            vec![500, 1000, 2000, 4000, 8000, 16000]
        };
        Self {
            msg: request,
            bytes: data,
            transport,
            from,
            to,
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
        fields(transaction_id = %self.msg.transaction_id()),
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
        StunRequestPollRet::SendData(send_data(self.transport, &self.bytes, self.from, self.to))
    }
}

/// A STUN Request
#[derive(Debug, Clone)]
pub struct StunRequest<'a> {
    agent: &'a StunAgent,
    transaction_id: TransactionId,
}

impl<'a> StunRequest<'a> {
    /// The request [`Message`]
    pub fn request(&self) -> &Message {
        let state = self.agent.request_state(self.transaction_id).unwrap();
        &state.msg
    }

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
    /// The request [`Message`]
    pub fn request(&self) -> &Message {
        let state = self.agent.request_state(self.transaction_id).unwrap();
        &state.msg
    }

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
pub enum HandleStunReply {
    /// The provided data could be parsed as a response to an outstanding request
    StunResponse(Message, Message),
    /// The provided data could be parsed as a STUN message
    IncomingStun(Message),
    /// The provided data could not be parsed as a STUN message
    Data(Vec<u8>),
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

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn agent_getters_setters() {
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
        init();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::new_request(BINDING);
        let transaction_id = msg.transaction_id();
        let transmit = agent.send(msg, remote_addr).unwrap();
        let now = Instant::now();
        assert_eq!(transmit.transport, TransportType::Udp);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);
        let request = Message::from_bytes(&transmit.data).unwrap();
        let response = Message::new_error(&request);
        let resp_data = response.to_bytes();
        let ret = agent.handle_incoming_data(&resp_data, remote_addr).unwrap();
        assert!(matches!(ret[0], HandleStunReply::StunResponse(_, _)));
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());

        let ret = agent.poll(now);
        assert!(matches!(ret, StunAgentPollRet::WaitUntil(_)));
    }

    #[test]
    fn indication_with_invalid_response() {
        init();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let transaction_id = Message::generate_transaction();
        let msg = Message::new(
            MessageType::from_class_method(MessageClass::Indication, BINDING),
            transaction_id,
        );
        let transmit = agent.send(msg, remote_addr).unwrap();
        assert_eq!(transmit.transport, TransportType::Udp);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);
        let _indication = Message::from_bytes(&transmit.data).unwrap();
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());
        // you should definitely never do this ;). Indications should never get replies.
        let response = Message::new(
            MessageType::from_class_method(MessageClass::Error, BINDING),
            transaction_id,
        );
        let resp_data = response.to_bytes();
        // response without a request is dropped.
        let ret = agent.handle_incoming_data(&resp_data, remote_addr).unwrap();
        assert!(ret.is_empty());
    }

    #[test]
    fn request_with_credentials() {
        init();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();
        let local_credentials = ShortTermCredentials::new(String::from("local_password"));
        let remote_credentials = ShortTermCredentials::new(String::from("remote_password"));
        agent.set_local_credentials(local_credentials.clone().into());
        agent.set_remote_credentials(remote_credentials.clone().into());

        // unvalidated peer data should be dropped
        let data = vec![20; 4];
        let replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        assert!(replies.is_empty());

        let mut msg = Message::new_request(BINDING);
        let transaction_id = msg.transaction_id();
        msg.add_message_integrity(&local_credentials.clone().into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        let transmit = agent.send(msg, remote_addr).unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::new_success(&request);
        response
            .add_attribute(XorMappedAddress::new(
                transmit.from,
                request.transaction_id(),
            ))
            .unwrap();
        response
            .add_message_integrity(&remote_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();

        let data = response.to_bytes();
        let to = transmit.to;
        let mut reply = agent.handle_incoming_data(&data, to).unwrap();
        let HandleStunReply::StunResponse(request, response) = reply.remove(0) else {
            unreachable!();
        };

        assert_eq!(request.transaction_id(), transaction_id);
        assert_eq!(response.transaction_id(), transaction_id);
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());

        let data = vec![20; 4];
        let mut replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        let HandleStunReply::Data(received) = replies.remove(0) else {
            unreachable!();
        };
        assert_eq!(data, received);
    }

    #[test]
    fn request_unanswered() {
        init();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::new_request(BINDING);
        let transaction_id = msg.transaction_id();
        agent.send(msg, remote_addr).unwrap();
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
        let data = vec![20; 4];
        let replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        assert!(replies.is_empty());
    }

    #[test]
    fn request_without_credentials() {
        init();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        // unvalidated peer data should be dropped
        let data = vec![20; 4];
        let replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        assert!(replies.is_empty());

        let msg = Message::new_request(BINDING);
        let transaction_id = msg.transaction_id();
        let transmit = agent.send(msg, remote_addr).unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::new_success(&request);
        response
            .add_attribute(XorMappedAddress::new(
                transmit.from,
                request.transaction_id(),
            ))
            .unwrap();

        let data = response.to_bytes();
        let to = transmit.to;
        let reply = agent.handle_incoming_data(&data, to).unwrap();

        assert!(matches!(reply[0], HandleStunReply::StunResponse(_, _)));
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());

        let data = vec![42; 8];
        let transmit = agent.send_data(&data, remote_addr);
        assert_eq!(transmit.data(), &data);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);

        let data = vec![20; 4];
        let mut replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        let HandleStunReply::Data(received) = replies.remove(0) else {
            unreachable!();
        };
        assert_eq!(data, received);
    }

    #[test]
    fn response_without_credentials() {
        init();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();
        let local_credentials = ShortTermCredentials::new(String::from("local_password"));
        let remote_credentials = ShortTermCredentials::new(String::from("remote_password"));
        agent.set_local_credentials(local_credentials.clone().into());
        agent.set_remote_credentials(remote_credentials.clone().into());

        let mut msg = Message::new_request(BINDING);
        let transaction_id = msg.transaction_id();
        msg.add_message_integrity(&local_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        let transmit = agent.send(msg, remote_addr).unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::new_success(&request);
        response
            .add_attribute(XorMappedAddress::new(
                transmit.from,
                request.transaction_id(),
            ))
            .unwrap();

        let data = response.to_bytes();
        let to = transmit.to;
        let reply = agent.handle_incoming_data(&data, to).unwrap();
        // reply is ignored as it does not have credentials
        assert!(reply.is_empty());
        assert!(agent.request_transaction(transaction_id).is_some());
        assert!(agent.mut_request_transaction(transaction_id).is_some());

        // unvalidated peer data should be dropped
        let data = vec![20; 4];
        let replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        assert!(replies.is_empty());
    }

    #[test]
    fn response_with_incorrect_credentials() {
        init();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();
        let local_credentials = ShortTermCredentials::new(String::from("local_password"));
        let remote_credentials = ShortTermCredentials::new(String::from("remote_password"));
        agent.set_local_credentials(local_credentials.clone().into());
        agent.set_remote_credentials(remote_credentials.into());

        let mut msg = Message::new_request(BINDING);
        msg.add_message_integrity(&local_credentials.clone().into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        let transmit = agent.send(msg, remote_addr).unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::new_success(&request);
        response
            .add_attribute(XorMappedAddress::new(
                transmit.from,
                request.transaction_id(),
            ))
            .unwrap();
        // wrong credentials, should be `remote_credentials`
        response
            .add_message_integrity(&local_credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();

        let data = response.to_bytes();
        let to = transmit.to;
        let reply = agent.handle_incoming_data(&data, to).unwrap();
        // reply is ignored as it does not have credentials
        assert!(reply.is_empty());

        // unvalidated peer data should be dropped
        let data = vec![20; 4];
        let replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        assert!(replies.is_empty());
    }

    #[test]
    fn duplicate_response_ignored() {
        init();
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        // unvalidated peer data should be dropped
        let data = vec![20; 4];
        let replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        assert!(replies.is_empty());

        let msg = Message::new_request(BINDING);
        let transmit = agent.send(msg, remote_addr).unwrap();

        let request = Message::from_bytes(&transmit.data).unwrap();

        let mut response = Message::new_success(&request);
        response
            .add_attribute(XorMappedAddress::new(
                transmit.from,
                request.transaction_id(),
            ))
            .unwrap();

        let data = response.to_bytes();
        let to = transmit.to;
        let reply = agent.handle_incoming_data(&data, to).unwrap();

        assert!(matches!(reply[0], HandleStunReply::StunResponse(_, _)));

        let data = vec![42; 8];
        let transmit = agent.send_data(&data, remote_addr);
        assert_eq!(transmit.data(), &data);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);

        let data = vec![20; 4];
        let mut replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        let HandleStunReply::Data(received) = replies.remove(0) else {
            unreachable!();
        };
        assert_eq!(data, received);

        let data = response.to_bytes();
        let reply = agent.handle_incoming_data(&data, to).unwrap();
        assert!(reply.is_empty());
    }

    #[test]
    fn tcp_request() {
        init();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::new_request(BINDING);
        let transmit = agent.send(msg, remote_addr).unwrap();
        let now = Instant::now();
        assert_eq!(transmit.transport, TransportType::Tcp);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);
        let request = Message::from_bytes(&transmit.data[2..]).unwrap();
        let response = Message::new_error(&request);
        let resp_data = response.to_bytes();
        let mut data = Vec::with_capacity(resp_data.len() + 2);
        data.resize(2, 0);
        BigEndian::write_u16(&mut data[..2], resp_data.len() as u16);
        data.extend(resp_data);
        let ret = agent.handle_incoming_data(&data, remote_addr).unwrap();
        assert!(matches!(ret[0], HandleStunReply::StunResponse(_, _)));

        let ret = agent.poll(now);
        assert!(matches!(ret, StunAgentPollRet::WaitUntil(_)));

        let data = vec![42; 8];
        let transmit = agent.send_data(&data, remote_addr);
        assert_eq!(&transmit.data()[2..], &data);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);

        let data = vec![0, 2, 4, 8];
        let mut replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        let HandleStunReply::Data(received) = replies.remove(0) else {
            unreachable!();
        };
        assert_eq!(&data[2..], received);
    }

    #[test]
    fn tcp_data_before_request() {
        init();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let data = [0, 2, 42, 42];

        assert!(matches!(
            agent.handle_incoming_data(&data, remote_addr),
            Err(StunError::ProtocolViolation)
        ));
    }

    #[test]
    fn tcp_split_recv() {
        init();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let mut agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::new_request(BINDING);

        let msg_data = msg.to_bytes();
        let mut data = Vec::with_capacity(msg_data.len() + 2);
        data.resize(2, 0);
        BigEndian::write_u16(&mut data[..2], msg_data.len() as u16);
        data.extend(msg_data);

        let ret = agent.handle_incoming_data(&data[..8], remote_addr).unwrap();
        assert!(ret.is_empty());
        let ret = agent.handle_incoming_data(&data[8..], remote_addr).unwrap();
        assert!(matches!(ret[0], HandleStunReply::IncomingStun(_)));
    }

    #[test]
    fn request_cancel() {
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        let msg = Message::new_request(BINDING);
        let transaction_id = msg.transaction_id();
        let _transmit = agent.send(msg, remote_addr).unwrap();

        let mut request = agent.mut_request_transaction(transaction_id).unwrap();
        assert_eq!(request.request().transaction_id(), transaction_id);
        assert_eq!(request.agent().local_addr(), local_addr);
        assert_eq!(request.mut_agent().local_addr(), local_addr);
        assert_eq!(request.peer_address(), remote_addr);
        request.cancel();

        let ret = agent.poll(Instant::now());
        let StunAgentPollRet::TransactionCancelled(request) = ret else {
            unreachable!();
        };
        assert_eq!(request.transaction_id(), transaction_id);
        assert!(agent.request_transaction(transaction_id).is_none());
        assert!(agent.mut_request_transaction(transaction_id).is_none());
    }

    #[test]
    fn request_cancel_send() {
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        let msg = Message::new_request(BINDING);
        let transaction_id = msg.transaction_id();
        let _transmit = agent.send(msg, remote_addr).unwrap();

        let mut request = agent.mut_request_transaction(transaction_id).unwrap();
        assert_eq!(request.request().transaction_id(), transaction_id);
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
    }

    #[test]
    fn request_duplicate() {
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        let msg = Message::new_request(BINDING);
        let transaction_id = msg.transaction_id();
        let transmit = agent.send(msg.clone(), remote_addr).unwrap();
        let to = transmit.to;

        let mut response = Message::new_success(&msg);
        response
            .add_attribute(XorMappedAddress::new(transmit.from, transaction_id))
            .unwrap();

        assert!(matches!(
            agent.send(msg, remote_addr),
            Err(StunError::AlreadyInProgress)
        ));

        // the original transaction should still exist
        let request = agent.request_transaction(transaction_id).unwrap();
        assert_eq!(request.request().transaction_id(), transaction_id);
        assert_eq!(request.peer_address(), remote_addr);

        let data = response.to_bytes();
        let mut reply = agent.handle_incoming_data(&data, to).unwrap();

        let HandleStunReply::StunResponse(request, response) = reply.remove(0) else {
            unreachable!();
        };
        assert_eq!(request.transaction_id(), transaction_id);
        assert_eq!(response.transaction_id(), transaction_id);

        let data = vec![20; 4];
        let mut replies = agent.handle_incoming_data(&data, remote_addr).unwrap();
        let HandleStunReply::Data(received) = replies.remove(0) else {
            unreachable!();
        };
        assert_eq!(data, received);
    }

    #[test]
    fn incoming_request() {
        let local_addr = "10.0.0.1:12345".parse().unwrap();
        let remote_addr = "10.0.0.2:3478".parse().unwrap();

        let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();

        let msg = Message::new_request(BINDING);
        let data = msg.to_bytes();
        let HandleStunReply::IncomingStun(request) = agent
            .handle_incoming_data(&data, remote_addr)
            .unwrap()
            .remove(0)
        else {
            unreachable!()
        };
        assert_eq!(msg.transaction_id(), request.transaction_id());
    }
}
