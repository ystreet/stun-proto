// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN

use std::error::Error;
use std::str::FromStr;

pub mod attribute;
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
#[derive(Debug)]
pub enum ParseTransportTypeError {
    UnknownTransport,
}

impl Error for ParseTransportTypeError {}

impl std::fmt::Display for ParseTransportTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
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
    pub use crate::attribute::{AttributeToRaw, AttributeFromRaw};
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Once;
    use tracing_subscriber::EnvFilter;

    static TRACING: Once = Once::new();

    pub fn test_init_log() {
        TRACING.call_once(|| {
            if let Ok(filter) = EnvFilter::try_from_default_env() {
                tracing_subscriber::fmt().with_env_filter(filter).init();
            }
        });
    }
}

