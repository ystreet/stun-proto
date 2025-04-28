// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;
use std::net::SocketAddr;

use crate::message::{StunParseError, TransactionId};

use super::{
    Attribute, AttributeFromRaw, AttributeStaticType, AttributeType, AttributeWrite,
    AttributeWriteExt, RawAttribute, XorSocketAddr,
};

/// The XorMappedAddress [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorMappedAddress {
    // stored XOR-ed as we need the transaction id to get the original value
    addr: XorSocketAddr,
}

impl AttributeStaticType for XorMappedAddress {
    const TYPE: AttributeType = AttributeType(0x0020);
}

impl Attribute for XorMappedAddress {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        self.addr.length()
    }
}

impl AttributeWrite for XorMappedAddress {
    fn to_raw(&self) -> RawAttribute {
        self.addr.to_raw(XorMappedAddress::TYPE)
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        self.addr.write_into_unchecked(&mut dest[4..])
    }
}

impl AttributeFromRaw<'_> for XorMappedAddress {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for XorMappedAddress {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..)?;
        Ok(Self {
            addr: XorSocketAddr::from_raw(raw)?,
        })
    }
}

impl XorMappedAddress {
    /// Create a new XorMappedAddress [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "127.0.0.1:1234".parse().unwrap();
    /// let mapped_addr = XorMappedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn new(addr: SocketAddr, transaction: TransactionId) -> Self {
        Self {
            addr: XorSocketAddr::new(addr, transaction),
        }
    }

    /// Retrieve the address stored in a XorMappedAddress
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "[::1]:1234".parse().unwrap();
    /// let mapped_addr = XorMappedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn addr(&self, transaction: TransactionId) -> SocketAddr {
        self.addr.addr(transaction)
    }
}

impl std::fmt::Display for XorMappedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", Self::TYPE, self.addr)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use byteorder::{BigEndian, ByteOrder};
    use tracing::trace;

    #[test]
    fn xor_mapped_address() {
        let _log = crate::tests::test_init_log();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        let addrs = &[
            "192.168.0.1:40000".parse().unwrap(),
            "[fd12:3456:789a:1::1]:41000".parse().unwrap(),
        ];
        for addr in addrs {
            let mapped = XorMappedAddress::new(*addr, transaction_id);
            trace!("mapped: {mapped}");
            assert_eq!(mapped.addr(transaction_id), *addr);
            let raw = RawAttribute::from(&mapped);
            trace!("{raw}");
            match addr.ip() {
                IpAddr::V4(_ip4) => assert_eq!(mapped.length(), 8),
                IpAddr::V6(_ip6) => assert_eq!(mapped.length(), 20),
            };
            assert_eq!(raw.get_type(), XorMappedAddress::TYPE);
            let mapped2 = XorMappedAddress::try_from(&raw).unwrap();
            assert_eq!(mapped2.addr(transaction_id), *addr);
            // truncate by one byte
            let mut data: Vec<_> = raw.clone().into();
            let len = data.len();
            BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
            assert!(matches!(
                XorMappedAddress::try_from(
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
                XorMappedAddress::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
                Err(StunParseError::WrongAttributeImplementation)
            ));
        }
    }
}
