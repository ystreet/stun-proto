// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # stun-types
//!
//! An implementation of parsing and writing STUN messages and attributes. This implementation is
//! trait based and supports definitions of [`Attribute`](attribute::Attribute)s that are external
//! to this crate.
//!
//! This is based on the following standards:
//! - [RFC8489]
//! - [RFC5389]
//! - [RFC3489]
//!
//! [RFC8489]: https://tools.ietf.org/html/rfc8489
//! [RFC5389]: https://tools.ietf.org/html/rfc5389
//! [RFC3489]: https://tools.ietf.org/html/rfc3489
//!
//! ## Examples
//!
//! See the [`message`] and [`attribute`] module documentation for examples on use.

use std::str::FromStr;

pub mod attribute;
pub mod data;
pub mod message;

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

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            TransportType::Udp => f.pad("UDP"),
            TransportType::Tcp => f.pad("TCP"),
        }
    }
}

pub mod prelude {
    pub use crate::attribute::{
        Attribute, AttributeExt, AttributeFromRaw, AttributeStaticType, AttributeWrite,
        AttributeWriteExt,
    };
}

#[cfg(test)]
pub(crate) mod tests {
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
}
