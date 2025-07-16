// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! # stun-proto
//!
//! A sans-IO implementation of a STUN agent as specified in [RFC5389] and [RFC8489].
//!
//! [RFC8489]: https://tools.ietf.org/html/rfc8489
//! [RFC5389]: https://tools.ietf.org/html/rfc5389
//!
//! ## Example
//!
//! ```
//! # use std::net::SocketAddr;
//! # use std::time::Instant;
//! use stun_proto::types::TransportType;
//! use stun_proto::types::attribute::{MessageIntegrity, XorMappedAddress};
//! use stun_proto::types::message::{
//!     BINDING, IntegrityAlgorithm, Message, MessageIntegrityCredentials,
//!     MessageWriteVec, ShortTermCredentials
//! };
//! use stun_proto::types::prelude::*;
//! use stun_proto::agent::{HandleStunReply, StunAgent};
//!
//! let local_addr = "10.0.0.1:12345".parse().unwrap();
//! let remote_addr = "10.0.0.2:3478".parse().unwrap();
//!
//! let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();
//!
//! // short term or long term credentials may optionally be configured on the agent.
//! let local_credentials = ShortTermCredentials::new(String::from("local_password"));
//! let remote_credentials = ShortTermCredentials::new(String::from("remote_password"));
//! agent.set_local_credentials(local_credentials.clone().into());
//! agent.set_remote_credentials(remote_credentials.clone().into());
//!
//! // and we can send a Message
//! let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
//! msg.add_message_integrity(&local_credentials.clone().into(), IntegrityAlgorithm::Sha1).unwrap();
//! let transmit = agent.send_request(msg.finish(), remote_addr, Instant::now()).unwrap();
//!
//! // The transmit struct indicates what data and where to send it.
//! let request = Message::from_bytes(&transmit.data).unwrap();
//!
//! let mut response = Message::builder_success(&request, MessageWriteVec::new());
//! let xor_addr = XorMappedAddress::new(transmit.from, request.transaction_id());
//! response.add_attribute(&xor_addr).unwrap();
//! response.add_message_integrity(&remote_credentials.clone().into(), IntegrityAlgorithm::Sha1).unwrap();
//!
//! // when receiving data on the associated socket, we should pass it through the Agent so it can
//! // parse and handle any STUN messages.
//! let data = response.finish();
//! let to = transmit.to;
//! let response = Message::from_bytes(&data).unwrap();
//! let reply = agent.handle_stun(response, to);
//!
//! // If running over TCP then there may be multiple messages parsed. However UDP will only ever
//! // have a single message per datagram.
//! assert!(matches!(reply, HandleStunReply::ValidatedStunResponse(_)));
//!
//! // Once valid STUN data has been sent and received, then data can be sent and received from the
//! // peer.
//! let data = vec![42; 8];
//! let transmit = agent.send_data(data.as_slice(), remote_addr);
//! assert_eq!(transmit.data, &data);
//! assert_eq!(transmit.from, local_addr);
//! assert_eq!(transmit.to, remote_addr);
//! ```

pub mod agent;

pub use stun_types as types;

#[derive(Clone)]
pub(crate) struct DebugWrapper<T>(&'static str, T);

impl<T> std::fmt::Debug for DebugWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl<T> std::ops::Deref for DebugWrapper<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.1
    }
}
impl<T> std::ops::DerefMut for DebugWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.1
    }
}
impl<T> DebugWrapper<T> {
    pub(crate) fn wrap(obj: T, name: &'static str) -> Self {
        Self(name, obj)
    }
}

/// Public prelude
pub mod prelude {}

#[cfg(test)]
pub(crate) mod tests {
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    pub fn test_init_log() -> DefaultGuard {
        let level_filter = std::env::var("STUN_LOG")
            .or(std::env::var("RUST_LOG"))
            .ok()
            .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
            .unwrap_or(
                tracing_subscriber::filter::Targets::new().with_default(tracing::Level::TRACE),
            );
        let registry = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_level(true)
                .with_target(false)
                .with_test_writer()
                .with_filter(level_filter),
        );
        tracing::subscriber::set_default(registry)
    }
}
