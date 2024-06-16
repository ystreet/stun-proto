// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN agent

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

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
#[derive(Debug, Clone)]
pub struct StunAgent {
    id: usize,
    transport: TransportType,
    local_addr: SocketAddr,
    remote_addr: Option<SocketAddr>,
    inner: DebugWrapper<Arc<StunAgentInner>>,
}

#[derive(Debug)]
struct StunAgentInner {
    state: Mutex<StunAgentState>,
}

#[derive(Debug)]
struct StunAgentState {
    #[allow(dead_code)]
    id: usize,
    validated_peers: HashSet<SocketAddr>,
    outstanding_requests: HashMap<TransactionId, Weak<StunRequestState>>,
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
        StunAgent {
            id,
            transport: self.transport,
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            inner: DebugWrapper::wrap(
                Arc::new(StunAgentInner {
                    state: Mutex::new(StunAgentState::new(id, self.transport)),
                }),
                "...",
            ),
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
    pub fn set_local_credentials(&self, credentials: MessageIntegrityCredentials) {
        let mut state = self.inner.state.lock().unwrap();
        state.local_credentials = Some(credentials)
    }

    /// The local credentials that all messages should be signed with
    pub fn local_credentials(&self) -> Option<MessageIntegrityCredentials> {
        let state = self.inner.state.lock().unwrap();
        state.local_credentials.clone()
    }

    /// Set the remote credentials that all messages should be signed with
    pub fn set_remote_credentials(&self, credentials: MessageIntegrityCredentials) {
        let mut state = self.inner.state.lock().unwrap();
        state.remote_credentials = Some(credentials)
    }

    /// The remote credentials that all messages should be signed with
    pub fn remote_credentials(&self) -> Option<MessageIntegrityCredentials> {
        let state = self.inner.state.lock().unwrap();
        state.remote_credentials.clone()
    }

    /// Perform any operations needed to be able to send data to a peer
    pub fn send_data<'a>(&self, bytes: &'a [u8], to: SocketAddr) -> Transmit<'a> {
        match self.transport {
            TransportType::Udp => Transmit::new(bytes, self.transport, self.local_addr, to),
            TransportType::Tcp => {
                let mut data = Vec::with_capacity(bytes.len() + 2);
                data.resize(2, 0);
                BigEndian::write_u16(&mut data, bytes.len() as u16);
                data.extend(bytes);
                Transmit::new_owned(data.into_boxed_slice(), self.transport, self.local_addr, to)
            }
        }
    }

    /// Perform any operations needed to be able to send a [`Message`] to a peer
    pub fn send(&self, msg: Message, to: SocketAddr) -> Result<Transmit<'_>, StunError> {
        let data = msg.to_bytes();
        Ok(self.send_data(&data, to).into_owned())
    }

    fn parse_chunk(
        &self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<Option<HandleStunReply>, StunError> {
        match Message::from_bytes(data) {
            Ok(stun_msg) => {
                debug!("received stun {}", stun_msg);
                let mut state = self.inner.state.lock().unwrap();
                state.handle_stun(stun_msg, data, from)
            }
            Err(_) => {
                let peer_validated = {
                    let state = self.inner.state.lock().unwrap();
                    state.validated_peers.contains(&from)
                };
                if peer_validated {
                    Ok(Some(HandleStunReply::Data(data.to_vec(), from)))
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
        &self,
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
                let mut state = self.inner.state.lock().unwrap();
                let tcp = state.tcp_buffer.as_mut().unwrap();
                tcp.push_data(data);
                let mut datas = vec![];
                while let Some(data) = tcp.pull_data() {
                    datas.push(data);
                }
                drop(state);
                for data in datas {
                    if let Some(reply) = self.parse_chunk(&data, from)? {
                        ret.push(reply);
                    }
                }
                Ok(ret)
            }
        }
    }

    /// Create a new [`StunRequest`] for encapsulating the state required for handling a
    /// [`MessageClass::Request`]
    pub fn stun_request_transaction(
        &self,
        msg: &Message,
        addr: SocketAddr,
    ) -> Result<StunRequest, StunError> {
        if !msg.has_class(MessageClass::Request) {
            return Err(StunError::WrongImplementation);
        }
        let timeouts_ms = if self.transport == TransportType::Tcp {
            vec![39500]
        } else {
            vec![500, 1000, 2000, 4000, 8000, 16000]
        };
        Ok(StunRequest(Arc::new(StunRequestState {
            msg: msg.clone(),
            to: addr,
            timeouts: timeouts_ms,
            agent: self.clone(),
            inner: Mutex::new(StunRequestInner {
                timeout_i: 0,
                recv_cancelled: false,
                send_cancelled: false,
                last_send_time: None,
                response: None,
            }),
        })))
    }
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
}

/// Return value for [`StunRequest::poll`]
#[derive(Debug)]
pub enum StunRequestPollRet<'a> {
    /// Wait until the specified time has passed
    WaitUntil(Instant),
    /// The request has been cancelled and will not make further progress
    Cancelled,
    /// Send data using the specified 5-tuple
    SendData(Transmit<'a>),
    /// A response for this request has been received.  No further progress will be made.
    Response(Message),
}

#[derive(Debug)]
struct StunRequestInner {
    response: Option<Message>,
    recv_cancelled: bool,
    send_cancelled: bool,
    timeout_i: usize,
    last_send_time: Option<Instant>,
}

#[derive(Debug)]
pub(crate) struct StunRequestState {
    msg: Message,
    to: SocketAddr,
    timeouts: Vec<u64>,
    agent: StunAgent,
    inner: Mutex<StunRequestInner>,
}

/// A STUN Request
#[derive(Debug, Clone)]
pub struct StunRequest(Arc<StunRequestState>);

impl StunRequest {
    /// The request [`Message`]
    pub fn request(&self) -> &Message {
        &self.0.msg
    }

    /// The remote address the request is sent to
    pub fn peer_address(&self) -> SocketAddr {
        self.0.to
    }

    /// Do not retransmit further
    pub fn cancel_retransmissions(&self) {
        let mut inner = self.0.inner.lock().unwrap();
        inner.send_cancelled = true;
    }

    /// Do not wait for any kind of response
    pub fn cancel(&self) {
        let mut inner = self.0.inner.lock().unwrap();
        inner.send_cancelled = true;
        inner.recv_cancelled = true;
    }

    /// Poll the request for further progress.  The returned value indicates the current state and
    /// anything the caller needs to perform.
    #[tracing::instrument(
        name = "stun_request_poll"
        level = "info",
        ret,
        err,
        skip(self),
        fields(transaction_id = %self.0.msg.transaction_id()),
    )]
    pub fn poll(&self, now: Instant) -> Result<StunRequestPollRet, StunError> {
        let weak_inner = Arc::downgrade(&self.0);
        let mut inner = self.0.inner.lock().unwrap();
        if let Some(response) = inner.response.clone() {
            return Ok(StunRequestPollRet::Response(response));
        }
        if inner.recv_cancelled {
            return Ok(StunRequestPollRet::Cancelled);
        }
        // TODO: account for TCP connect in timeout
        if let Some(last_send) = inner.last_send_time {
            if inner.timeout_i >= self.0.timeouts.len() {
                return Err(StunError::TimedOut);
            }
            let next_send = last_send + Duration::from_millis(self.0.timeouts[inner.timeout_i]);
            if next_send > now {
                return Ok(StunRequestPollRet::WaitUntil(next_send));
            }
            inner.timeout_i += 1;
        }
        if inner.send_cancelled {
            return Ok(StunRequestPollRet::Cancelled);
        }
        inner.last_send_time = Some(now);
        drop(inner);
        let mut agent_inner = self.0.agent.inner.state.lock().unwrap();
        agent_inner
            .outstanding_requests
            .insert(self.0.msg.transaction_id(), weak_inner);
        drop(agent_inner);
        Ok(StunRequestPollRet::SendData(
            self.0.agent.send(self.0.msg.clone(), self.0.to)?,
        ))
    }

    /// The [`StunAgent`] this request is being sent with.
    pub fn agent(&self) -> &StunAgent {
        &self.0.agent
    }
}

/// Return value when handling possible STUN data
#[derive(Debug)]
pub enum HandleStunReply {
    /// The provided data could be parsed as a STUN message
    Stun(Message, SocketAddr),
    /// The provided data could not be parsed as a STUN message
    Data(Vec<u8>, SocketAddr),
}

/// STUN errors
#[derive(Debug)]
pub enum StunError {
    Failed,
    WrongImplementation,
    AlreadyExists,
    AlreadyInProgress,
    ResourceNotFound,
    TimedOut,
    IntegrityCheckFailed,
    ProtocolViolation,
    ParseError(StunParseError),
    WriteError(StunWriteError),
    Aborted,
}

impl std::error::Error for StunError {}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<StunParseError> for StunError {
    fn from(e: StunParseError) -> Self {
        match e {
            StunParseError::WrongImplementation => StunError::WrongImplementation,
            StunParseError::NoIntegrity => StunError::ResourceNotFound,
            StunParseError::IntegrityCheckFailed => StunError::IntegrityCheckFailed,
            _ => StunError::ParseError(e),
        }
    }
}

impl From<StunWriteError> for StunError {
    fn from(e: StunWriteError) -> Self {
        match e {
            StunWriteError::WrongImplementation => StunError::WrongImplementation,
            _ => StunError::WriteError(e),
        }
    }
}

impl StunAgentState {
    fn new(id: usize, transport: TransportType) -> Self {
        let tcp_buffer = match transport {
            TransportType::Udp => None,
            TransportType::Tcp => Some(TcpBuffer::new()),
        };

        Self {
            id,
            outstanding_requests: HashMap::new(),
            validated_peers: HashSet::new(),
            local_credentials: None,
            remote_credentials: None,
            tcp_buffer,
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
            if let Some(weak_request) = self.take_outstanding_request(&msg.transaction_id()) {
                let request = match weak_request.upgrade() {
                    Some(request) => request,
                    None => {
                        trace!("original request disappeared -> ignoring response");
                        return Ok(None);
                    }
                };
                // only validate response if the original request had credentials
                if request.msg.attribute::<MessageIntegrity>().is_some() {
                    if let Some(remote_creds) = &self.remote_credentials {
                        match msg.validate_integrity(orig_data, remote_creds) {
                            Ok(_) => {
                                self.validated_peer(from);
                                request.inner.lock().unwrap().response = Some(msg.clone());
                                Ok(Some(HandleStunReply::Stun(msg, from)))
                            }
                            Err(e) => {
                                debug!("message failed integrity check: {:?}", e);
                                self.outstanding_requests
                                    .insert(msg.transaction_id(), weak_request);
                                Ok(None)
                            }
                        }
                    } else {
                        debug!("no remote credentials, ignoring");
                        self.outstanding_requests
                            .insert(msg.transaction_id(), weak_request);
                        Ok(None)
                    }
                } else {
                    // original message didn't have integrity, reply doesn't need to either
                    self.validated_peer(from);
                    request.inner.lock().unwrap().response = Some(msg.clone());
                    Ok(Some(HandleStunReply::Stun(msg, from)))
                }
            } else {
                debug!("unmatched stun response, dropping {}", msg);
                // unmatched response -> drop
                Ok(None)
            }
        } else {
            self.validated_peer(from);
            Ok(Some(HandleStunReply::Stun(msg, from)))
        }
    }

    #[tracing::instrument(skip(self, transaction_id),
        fields(transaction_id = %transaction_id))]
    fn take_outstanding_request(
        &mut self,
        transaction_id: &TransactionId,
    ) -> Option<Weak<StunRequestState>> {
        if let Some(request) = self.outstanding_requests.remove(transaction_id) {
            trace!("removing request");
            Some(request)
        } else {
            trace!("no outstanding request");
            None
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn request() {
        init();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::new_request(BINDING);
        let request = agent.stun_request_transaction(&msg, remote_addr).unwrap();
        let now = Instant::now();
        let ret = request.poll(now).unwrap();
        assert!(matches!(ret, StunRequestPollRet::SendData(_)));
        if let StunRequestPollRet::SendData(Transmit {
            data,
            transport,
            from,
            to,
        }) = ret
        {
            assert_eq!(transport, TransportType::Udp);
            assert_eq!(from, local_addr);
            assert_eq!(to, remote_addr);
            let request = Message::from_bytes(&data).unwrap();
            let response = Message::new_error(&request);
            let resp_data = response.to_bytes();
            let ret = agent.handle_incoming_data(&resp_data, remote_addr).unwrap();
            assert!(matches!(ret[0], HandleStunReply::Stun(_, _)));
        } else {
            unreachable!();
        }
        let ret = request.poll(now).unwrap();
        assert!(matches!(ret, StunRequestPollRet::Response(_)));
    }

    #[test]
    fn request_unanswered() {
        init();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::new_request(BINDING);
        let request = agent.stun_request_transaction(&msg, remote_addr).unwrap();
        let mut now = Instant::now();
        loop {
            match request.poll(now) {
                Ok(StunRequestPollRet::WaitUntil(new_now)) => {
                    now = new_now;
                }
                Ok(StunRequestPollRet::SendData(_)) => (),
                Err(StunError::TimedOut) => break,
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn tcp_request() {
        init();
        let local_addr = "127.0.0.1:2000".parse().unwrap();
        let remote_addr = "127.0.0.1:1000".parse().unwrap();
        let agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let msg = Message::new_request(BINDING);
        let request = agent.stun_request_transaction(&msg, remote_addr).unwrap();
        let now = Instant::now();
        let ret = request.poll(now).unwrap();
        if let StunRequestPollRet::SendData(Transmit {
            data,
            transport,
            from,
            to,
        }) = ret
        {
            assert_eq!(transport, TransportType::Tcp);
            assert_eq!(from, local_addr);
            assert_eq!(to, remote_addr);
            let request = Message::from_bytes(&data[2..]).unwrap();
            let response = Message::new_error(&request);
            let resp_data = response.to_bytes();
            let mut data = Vec::with_capacity(resp_data.len() + 2);
            data.resize(2, 0);
            BigEndian::write_u16(&mut data[..2], resp_data.len() as u16);
            data.extend(resp_data);
            let ret = agent.handle_incoming_data(&data, remote_addr).unwrap();
            assert!(matches!(ret[0], HandleStunReply::Stun(_, _)));
        } else {
            unreachable!();
        }
        let ret = request.poll(now).unwrap();
        assert!(matches!(ret, StunRequestPollRet::Response(_)));
    }
}
