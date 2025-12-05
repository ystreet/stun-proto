// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use core::convert::TryFrom;
use core::net::SocketAddr;

use crate::message::StunParseError;

use super::{
    Attribute, AttributeExt, AttributeFromRaw, AttributeStaticType, AttributeType, AttributeWrite,
    AttributeWriteExt, MappedSocketAddr, RawAttribute,
};

/// The AlternateServer [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateServer {
    addr: MappedSocketAddr,
}

impl AttributeStaticType for AlternateServer {
    const TYPE: AttributeType = AttributeType(0x8023);
}
impl Attribute for AlternateServer {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        self.addr.length()
    }
}

impl AttributeWrite for AlternateServer {
    fn to_raw(&self) -> RawAttribute<'_> {
        self.addr.to_raw(AlternateServer::TYPE)
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        self.addr.write_into_unchecked(&mut dest[4..]);
    }
}

impl AttributeFromRaw<'_> for AlternateServer {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError> {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for AlternateServer {
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

impl core::fmt::Display for AlternateServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", AlternateServer::TYPE, self.addr)
    }
}

/// The AlternateDomain [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateDomain {
    domain: String,
}

impl AttributeStaticType for AlternateDomain {
    const TYPE: AttributeType = AttributeType(0x8003);
}

impl Attribute for AlternateDomain {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }
    fn length(&self) -> u16 {
        self.domain.len() as u16
    }
}
impl AttributeFromRaw<'_> for AlternateDomain {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}
impl TryFrom<&RawAttribute<'_>> for AlternateDomain {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..)?;
        // FIXME: should be ascii-only
        Ok(Self {
            domain: core::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidAttributeData)?
                .to_owned(),
        })
    }
}
impl AttributeWrite for AlternateDomain {
    fn to_raw(&self) -> RawAttribute<'_> {
        RawAttribute::new(AlternateDomain::TYPE, self.domain.as_bytes())
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        let len = self.padded_len();
        self.write_header_unchecked(dest);
        dest[4..4 + self.domain.len()].copy_from_slice(self.domain.as_bytes());
        let offset = 4 + self.domain.len();
        if len > offset {
            dest[offset..len].fill(0);
        }
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

impl core::fmt::Display for AlternateDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", AlternateDomain::TYPE, self.domain)
    }
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use byteorder::{BigEndian, ByteOrder};
    use tracing::trace;

    const ADDRS: [SocketAddr; 2] = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 40000),
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                0xfd2, 0x3456, 0x789a, 0x01, 0x0, 0x0, 0x0, 0x1,
            )),
            41000,
        ),
    ];

    #[test]
    fn alternate_server() {
        let _log = crate::tests::test_init_log();
        for addr in ADDRS {
            let mapped = AlternateServer::new(addr);
            trace!("{mapped}");
            assert_eq!(mapped.server(), addr);
            match addr {
                SocketAddr::V4(_) => assert_eq!(mapped.length(), 8),
                SocketAddr::V6(_) => assert_eq!(mapped.length(), 20),
            }
        }
    }

    #[test]
    fn alternate_server_raw() {
        let _log = crate::tests::test_init_log();
        for addr in ADDRS {
            let mapped = AlternateServer::new(addr);
            let raw = RawAttribute::from(&mapped);
            match addr {
                SocketAddr::V4(_) => assert_eq!(raw.length(), 8),
                SocketAddr::V6(_) => assert_eq!(raw.length(), 20),
            }
            trace!("{raw}");
            assert_eq!(raw.get_type(), AlternateServer::TYPE);
            let mapped2 = AlternateServer::try_from(&raw).unwrap();
            assert_eq!(mapped2.server(), addr);
        }
    }

    #[test]
    fn alternate_server_raw_short() {
        let _log = crate::tests::test_init_log();
        for addr in ADDRS {
            let mapped = AlternateServer::new(addr);
            let raw = RawAttribute::from(&mapped);
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
        }
    }

    #[test]
    fn alternate_server_raw_wrong_type() {
        let _log = crate::tests::test_init_log();
        for addr in ADDRS {
            let mapped = AlternateServer::new(addr);
            let raw = RawAttribute::from(&mapped);
            // provide incorrectly typed data
            let mut data: Vec<_> = raw.clone().into();
            BigEndian::write_u16(&mut data[0..2], 0);
            assert!(matches!(
                AlternateServer::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
                Err(StunParseError::WrongAttributeImplementation)
            ));
        }
    }

    #[test]
    fn alternate_server_write_into() {
        let _log = crate::tests::test_init_log();
        for addr in ADDRS {
            let mapped = AlternateServer::new(addr);
            let raw = RawAttribute::from(&mapped);

            let mut dest = vec![0; raw.padded_len()];
            mapped.write_into(&mut dest).unwrap();
            let raw = RawAttribute::from_bytes(&dest).unwrap();
            let mapped2 = AlternateServer::try_from(&raw).unwrap();
            assert_eq!(mapped2.server(), addr);
        }
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn alternate_server_write_into_unchecked() {
        let _log = crate::tests::test_init_log();
        let mapped = AlternateServer::new(ADDRS[0]);
        let raw = RawAttribute::from(&mapped);

        let mut dest = vec![0; raw.padded_len() - 1];
        mapped.write_into_unchecked(&mut dest);
    }

    const DOMAIN: &str = "example.com";

    #[test]
    fn alternative_domain() {
        let _log = crate::tests::test_init_log();
        let attr = AlternateDomain::new(DOMAIN);
        trace!("{attr}");
        assert_eq!(attr.domain(), DOMAIN);
        assert_eq!(attr.length() as usize, DOMAIN.len());
    }

    #[test]
    fn alternative_domain_raw() {
        let _log = crate::tests::test_init_log();
        let attr = AlternateDomain::new(DOMAIN);
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
        assert_eq!(raw.get_type(), AlternateDomain::TYPE);
        let mapped2 = AlternateDomain::try_from(&raw).unwrap();
        assert_eq!(mapped2.domain(), DOMAIN);
    }

    #[test]
    fn alternative_domain_raw_wrong_type() {
        let _log = crate::tests::test_init_log();
        let attr = AlternateDomain::new(DOMAIN);
        let raw = RawAttribute::from(&attr);
        let mut data: Vec<_> = raw.clone().into();
        // provide incorrectly typed data
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            AlternateDomain::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn alternative_domain_raw_invalid_utf8() {
        let _log = crate::tests::test_init_log();
        let attr = AlternateDomain::new(DOMAIN);
        let raw = RawAttribute::from(&attr);

        // invalid utf-8 data
        let mut data: Vec<_> = raw.clone().into();
        data[8] = 0x88;
        assert!(matches!(
            AlternateDomain::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::InvalidAttributeData)
        ));
    }

    #[test]
    fn alternative_domain_write_into() {
        let _log = crate::tests::test_init_log();
        let attr = AlternateDomain::new(DOMAIN);
        let raw = RawAttribute::from(&attr);

        let mut dest = vec![0; raw.padded_len()];
        attr.write_into(&mut dest).unwrap();
        let raw = RawAttribute::from_bytes(&dest).unwrap();
        let mapped2 = AlternateDomain::try_from(&raw).unwrap();
        assert_eq!(mapped2.domain(), DOMAIN);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn alternative_domain_write_into_unchecked() {
        let _log = crate::tests::test_init_log();
        let attr = AlternateDomain::new(DOMAIN);
        let raw = RawAttribute::from(&attr);

        let mut dest = vec![0; raw.padded_len() - 1];
        attr.write_into_unchecked(&mut dest);
    }
}
