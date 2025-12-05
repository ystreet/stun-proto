// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::convert::TryFrom;
use core::net::SocketAddr;

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
    fn to_raw(&self) -> RawAttribute<'_> {
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
    /// # use core::net::SocketAddr;
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
    /// # use core::net::SocketAddr;
    /// let addr = "[::1]:1234".parse().unwrap();
    /// let mapped_addr = XorMappedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn addr(&self, transaction: TransactionId) -> SocketAddr {
        self.addr.addr(transaction)
    }
}

impl core::fmt::Display for XorMappedAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", Self::TYPE, self.addr)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::prelude::AttributeExt;

    use super::*;
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
    fn xor_mapped_address() {
        let _log = crate::tests::test_init_log();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        for addr in ADDRS {
            let mapped = XorMappedAddress::new(addr, transaction_id);
            trace!("mapped: {mapped}");
            assert_eq!(mapped.addr(transaction_id), addr);
            match addr.ip() {
                IpAddr::V4(_ip4) => assert_eq!(mapped.length(), 8),
                IpAddr::V6(_ip6) => assert_eq!(mapped.length(), 20),
            };
        }
    }

    #[test]
    fn xor_mapped_address_raw() {
        let _log = crate::tests::test_init_log();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        for addr in ADDRS {
            let mapped = XorMappedAddress::new(addr, transaction_id);
            let raw = RawAttribute::from(&mapped);
            match addr.ip() {
                IpAddr::V4(_ip4) => assert_eq!(raw.length(), 8),
                IpAddr::V6(_ip6) => assert_eq!(raw.length(), 20),
            };
            trace!("{raw}");
            assert_eq!(raw.get_type(), XorMappedAddress::TYPE);
            let mapped2 = XorMappedAddress::try_from(&raw).unwrap();
            assert_eq!(mapped2.addr(transaction_id), addr);
        }
    }

    #[test]
    fn xor_mapped_address_raw_short() {
        let _log = crate::tests::test_init_log();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        for addr in ADDRS {
            let mapped = XorMappedAddress::new(addr, transaction_id);
            let raw = RawAttribute::from(&mapped);
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
        }
    }

    #[test]
    fn xor_mapped_address_raw_wrong_type() {
        let _log = crate::tests::test_init_log();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        for addr in ADDRS {
            let mapped = XorMappedAddress::new(addr, transaction_id);
            let raw = RawAttribute::from(&mapped);
            // provide incorrectly typed data
            let mut data: Vec<_> = raw.into();
            BigEndian::write_u16(&mut data[0..2], 0);
            assert!(matches!(
                XorMappedAddress::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
                Err(StunParseError::WrongAttributeImplementation)
            ));
        }
    }

    #[test]
    fn xor_mapped_address_write_into() {
        let _log = crate::tests::test_init_log();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        for addr in ADDRS {
            let mapped = XorMappedAddress::new(addr, transaction_id);
            let raw = RawAttribute::from(&mapped);

            let mut dest = vec![0; raw.padded_len()];
            mapped.write_into(&mut dest).unwrap();
            let raw = RawAttribute::from_bytes(&dest).unwrap();
            let mapped2 = XorMappedAddress::try_from(&raw).unwrap();
            assert_eq!(mapped2.addr(transaction_id), addr);
        }
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn xor_mapped_address_write_into_unchecked() {
        let _log = crate::tests::test_init_log();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        let mapped = XorMappedAddress::new(ADDRS[0], transaction_id);
        let raw = RawAttribute::from(&mapped);

        let mut dest = vec![0; raw.padded_len() - 1];
        mapped.write_into_unchecked(&mut dest);
    }
}
