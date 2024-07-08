// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;
use std::net::SocketAddr;

use crate::message::StunParseError;

use super::{Attribute, AttributeType, MappedSocketAddr, RawAttribute};

/// The AlternateServer [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateServer {
    addr: MappedSocketAddr,
}

impl Attribute for AlternateServer {
    const TYPE: AttributeType = AttributeType(0x8023);

    fn length(&self) -> u16 {
        self.addr.length()
    }
}

impl<'a> From<&AlternateServer> for RawAttribute<'a> {
    fn from(value: &AlternateServer) -> RawAttribute<'a> {
        value.addr.to_raw(AlternateServer::TYPE)
    }
}

impl<'a> TryFrom<&RawAttribute<'a>> for AlternateServer {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..)?;
        let addr = MappedSocketAddr::from_raw(raw)?;
        Ok(Self { addr })
    }
}

impl AlternateServer {
    /// Create a new AlternateServer [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let addr = "127.0.0.1:12345".parse().unwrap();
    /// let server = AlternateServer::new(addr);
    /// assert_eq!(server.server(), addr);
    /// ```
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr: MappedSocketAddr::new(addr),
        }
    }

    /// Retrieve the server value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let addr = "127.0.0.1:12345".parse().unwrap();
    /// let server = AlternateServer::new(addr);
    /// assert_eq!(server.server(), addr);
    /// ```
    pub fn server(&self) -> SocketAddr {
        self.addr.addr()
    }
}

impl std::fmt::Display for AlternateServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", AlternateServer::TYPE, self.addr)
    }
}

/// The AlternateDomain [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateDomain {
    domain: String,
}

impl Attribute for AlternateDomain {
    const TYPE: AttributeType = AttributeType(0x8003);

    fn length(&self) -> u16 {
        self.domain.len() as u16
    }
}
impl<'a> TryFrom<&RawAttribute<'a>> for AlternateDomain {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..)?;
        // FIXME: should be ascii-only
        Ok(Self {
            domain: std::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidAttributeData)?
                .to_owned(),
        })
    }
}
impl<'a> From<&AlternateDomain> for RawAttribute<'a> {
    fn from(value: &AlternateDomain) -> RawAttribute<'a> {
        RawAttribute::new(AlternateDomain::TYPE, value.domain.as_bytes()).into_owned()
    }
}

impl AlternateDomain {
    /// Create a new AlternateDomain [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let dns = "example.com";
    /// let domain = AlternateDomain::new(dns);
    /// assert_eq!(domain.domain(), dns);
    /// ```
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
        }
    }

    /// Retrieve the domain value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let dns = "example.com";
    /// let domain = AlternateDomain::new(dns);
    /// assert_eq!(domain.domain(), dns);
    /// ```
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl std::fmt::Display for AlternateDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", AlternateDomain::TYPE, self.domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};

    #[test]
    fn alternate_server() {
        let _log = crate::tests::test_init_log();
        let addrs = &[
            "192.168.0.1:40000".parse().unwrap(),
            "[fd12:3456:789a:1::1]:41000".parse().unwrap(),
        ];
        for addr in addrs {
            let mapped = AlternateServer::new(*addr);
            assert_eq!(mapped.server(), *addr);
            match addr {
                SocketAddr::V4(_) => assert_eq!(mapped.length(), 8),
                SocketAddr::V6(_) => assert_eq!(mapped.length(), 20),
            }
            let raw = RawAttribute::from(&mapped);
            assert_eq!(raw.get_type(), AlternateServer::TYPE);
            let mapped2 = AlternateServer::try_from(&raw).unwrap();
            assert_eq!(mapped2.server(), *addr);
            // truncate by one byte
            let mut data: Vec<_> = raw.clone().into();
            let len = data.len();
            BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
            assert!(matches!(
                AlternateServer::try_from(
                    &RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()
                ),
                Err(StunParseError::Truncated {
                    expected: _,
                    actual: _
                })
            ));
            // provide incorrectly typed data
            let mut data: Vec<_> = raw.into();
            BigEndian::write_u16(&mut data[0..2], 0);
            assert!(matches!(
                AlternateServer::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
                Err(StunParseError::WrongAttributeImplementation)
            ));
        }
    }

    #[test]
    fn alternative_domain() {
        let _log = crate::tests::test_init_log();
        let dns = "example.com";
        let attr = AlternateDomain::new(dns);
        assert_eq!(attr.domain(), dns);
        assert_eq!(attr.length() as usize, dns.len());
        let raw = RawAttribute::from(&attr);
        assert_eq!(raw.get_type(), AlternateDomain::TYPE);
        let mapped2 = AlternateDomain::try_from(&raw).unwrap();
        assert_eq!(mapped2.domain(), dns);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            AlternateDomain::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
