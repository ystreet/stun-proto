// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! # stun-types
//!
//! An implementation of parsing and writing STUN messages and attributes based on trait
//! implementations.
//!
//! This is based on the following standards:
//! - [RFC8489] - 'Session Traversal Utilities for NAT (STUN)'
//! - [RFC5389] - 'Session Traversal Utilities for NAT (STUN)'
//! - [RFC3489] - 'STUN - Simple Traversal of User Datagram Protocol (UDP)
//!   Through Network Address Translators (NATs)'
//!
//! ## [Message](crate::message::Message)
//!
//! ### Message Parsing
//!
//! Message parsing is zerocopy by default through the [`RawAttribute`](crate::attribute::RawAttribute)
//! struct. Converting to a concrete attribute implementation (such as
//! [`Software`](crate::attribute::Software)) may incur a copy depending on the attribute
//! implementation.
//!
//! ### Message writing
//!
//! The destination for a written Message is completely customizable through the
//! [`MessageWrite`](crate::message::MessageWrite) trait. It is therefore possible to write directly
//! into network provided buffers for increased performance and throughput.
//!
//! [`MessageWriteVec`](crate::message::MessageWriteVec) provides a simple implementation of
//! message writing that will write into a newly allocated `Vec<u8>`.
//!
//! ## [Attribute](crate::attribute::Attribute)
//!
//! An [`Attribute`](crate::attribute::Attribute) implementation can be implemented entirely
//! outside of this crate and used exactly the same as an Attribute implemented within this crate.
//! Look at [`attribute`] module level documentation for an example of defining your own
//! [`Attribute`](crate::attribute::Attribute).
//!
//! For TURN-related attributes, have a look at the [turn-types] crate which uses this crate to
//! implement STUN attributes for TURN.
//!
//! [RFC8489]: https://tools.ietf.org/html/rfc8489
//! [RFC5389]: https://tools.ietf.org/html/rfc5389
//! [RFC3489]: https://tools.ietf.org/html/rfc3489
//! [turn-types]: https://docs.rs/turn-types/latest/turn_types/
//!
//! ## Examples
//!
//! See the [`message`] and [`attribute`] module documentation for examples of use.

#![no_std]

use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
};

use crate::message::StunParseError;

pub mod attribute;
pub mod data;
pub mod message;

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

/// The transport family
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TransportType {
    /// The UDP transport
    Udp,
    /// The TCP transport
    Tcp,
}

/// Errors when parsing a [`TransportType`]
#[derive(Debug, thiserror::Error)]
pub enum ParseTransportTypeError {
    /// An unknown transport value was provided
    #[error("Unknown transport value was provided")]
    UnknownTransport,
}

impl FromStr for TransportType {
    type Err = ParseTransportTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UDP" => Ok(TransportType::Udp),
            "TCP" => Ok(TransportType::Tcp),
            _ => Err(ParseTransportTypeError::UnknownTransport),
        }
    }
}

impl core::fmt::Display for TransportType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self {
            TransportType::Udp => f.pad("UDP"),
            TransportType::Tcp => f.pad("TCP"),
        }
    }
}

/// The address family of a socket
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IP version 4 address.
    IPV4,
    /// IP version 6 address.
    IPV6,
}

impl AddressFamily {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            AddressFamily::IPV4 => 0x1,
            AddressFamily::IPV6 => 0x2,
        }
    }

    pub(crate) fn from_byte(byte: u8) -> Result<AddressFamily, StunParseError> {
        match byte {
            0x1 => Ok(AddressFamily::IPV4),
            0x2 => Ok(AddressFamily::IPV6),
            _ => Err(StunParseError::InvalidAttributeData),
        }
    }
}

impl From<&SocketAddr> for AddressFamily {
    fn from(value: &SocketAddr) -> Self {
        match value {
            SocketAddr::V4(_) => Self::IPV4,
            SocketAddr::V6(_) => Self::IPV6,
        }
    }
}

impl From<&SocketAddrV4> for AddressFamily {
    fn from(_value: &SocketAddrV4) -> Self {
        Self::IPV4
    }
}

impl From<&SocketAddrV6> for AddressFamily {
    fn from(_value: &SocketAddrV6) -> Self {
        Self::IPV6
    }
}

impl From<&IpAddr> for AddressFamily {
    fn from(value: &IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self::IPV4,
            IpAddr::V6(_) => Self::IPV6,
        }
    }
}

impl From<&Ipv4Addr> for AddressFamily {
    fn from(_value: &Ipv4Addr) -> Self {
        Self::IPV4
    }
}

impl From<&Ipv6Addr> for AddressFamily {
    fn from(_value: &Ipv6Addr) -> Self {
        Self::IPV6
    }
}

impl core::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AddressFamily::IPV4 => write!(f, "IPV4"),
            AddressFamily::IPV6 => write!(f, "IPV6"),
        }
    }
}

/// Prelude module for traits
pub mod prelude {
    pub use crate::attribute::{
        Attribute, AttributeExt, AttributeFromRaw, AttributeStaticType, AttributeWrite,
        AttributeWriteExt,
    };
    pub use crate::message::{MessageWrite, MessageWriteExt};
}

#[cfg(test)]
pub(crate) mod tests {
    use alloc::borrow::ToOwned;
    use alloc::format;
    use alloc::string::{String, ToString};
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    use super::*;

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

    #[test]
    fn parse_transport_type() {
        assert!(matches!("UDP".parse(), Ok(TransportType::Udp)));
        assert!(matches!("TCP".parse(), Ok(TransportType::Tcp)));
        assert!(matches!(
            TransportType::from_str("Random"),
            Err(ParseTransportTypeError::UnknownTransport)
        ));
    }

    #[test]
    fn transport_type_str() {
        assert_eq!(TransportType::Udp.to_string(), String::from("UDP"));
        assert_eq!(TransportType::Tcp.to_string(), String::from("TCP"));
    }

    #[test]
    fn address_family() {
        assert_eq!(AddressFamily::IPV4.to_byte(), 1);
        assert_eq!(AddressFamily::from_byte(1).unwrap(), AddressFamily::IPV4);
        assert_eq!(format!("{}", AddressFamily::IPV4), "IPV4".to_owned());
        assert_eq!(AddressFamily::IPV6.to_byte(), 2);
        assert_eq!(AddressFamily::from_byte(2).unwrap(), AddressFamily::IPV6);
        assert_eq!(format!("{}", AddressFamily::IPV6), "IPV6".to_owned());
        assert!(matches!(
            AddressFamily::from_byte(3),
            Err(StunParseError::InvalidAttributeData)
        ));
        let ipv4_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(AddressFamily::from(&ipv4_addr), AddressFamily::IPV4);
        assert_eq!(AddressFamily::from(&ipv4_addr.ip()), AddressFamily::IPV4);
        let SocketAddr::V4(ipv4_addr) = ipv4_addr else {
            unreachable!();
        };
        assert_eq!(AddressFamily::from(&ipv4_addr), AddressFamily::IPV4);
        assert_eq!(AddressFamily::from(ipv4_addr.ip()), AddressFamily::IPV4);
        let ipv6_addr: SocketAddr = "[::1]:1".parse().unwrap();
        assert_eq!(AddressFamily::from(&ipv6_addr), AddressFamily::IPV6);
        assert_eq!(AddressFamily::from(&ipv6_addr.ip()), AddressFamily::IPV6);
        let SocketAddr::V6(ipv6_addr) = ipv6_addr else {
            unreachable!();
        };
        assert_eq!(AddressFamily::from(&ipv6_addr), AddressFamily::IPV6);
        assert_eq!(AddressFamily::from(ipv6_addr.ip()), AddressFamily::IPV6);
    }
}
