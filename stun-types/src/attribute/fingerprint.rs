// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;

use crate::message::StunParseError;

use super::{Attribute, AttributeType, RawAttribute};

/// The Fingerprint [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    fingerprint: [u8; 4],
}

impl Attribute for Fingerprint {
    const TYPE: AttributeType = AttributeType(0x8028);

    fn length(&self) -> u16 {
        4
    }
}
impl From<Fingerprint> for RawAttribute {
    fn from(value: Fingerprint) -> RawAttribute {
        let buf = bytewise_xor!(4, value.fingerprint, Fingerprint::XOR_CONSTANT, 0);
        RawAttribute::new(Fingerprint::TYPE, &buf)
    }
}
impl TryFrom<&RawAttribute> for Fingerprint {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..=4)?;
        // sized checked earlier
        let boxed: Box<[u8; 4]> = raw.value.clone().into_boxed_slice().try_into().unwrap();
        let fingerprint = bytewise_xor!(4, *boxed, Fingerprint::XOR_CONSTANT, 0);
        Ok(Self { fingerprint })
    }
}

impl Fingerprint {
    const XOR_CONSTANT: [u8; 4] = [0x53, 0x54, 0x55, 0x4E];

    /// Create a new Fingerprint [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let value = [0;4];
    /// let fingerprint = Fingerprint::new(value);
    /// assert_eq!(fingerprint.fingerprint(), &value);
    /// ```
    pub fn new(fingerprint: [u8; 4]) -> Self {
        Self { fingerprint }
    }

    /// Retrieve the fingerprint value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let value = [0;4];
    /// let fingerprint = Fingerprint::new(value);
    /// assert_eq!(fingerprint.fingerprint(), &value);
    /// ```
    pub fn fingerprint(&self) -> &[u8; 4] {
        &self.fingerprint
    }

    /// Compute the fingerprint of a specified block of data as required by STUN
    ///
    /// # Examples
    /// ```
    /// # use stun_types::attribute::*;
    /// let value = [99;4];
    /// assert_eq!(Fingerprint::compute(&value), [216, 45, 250, 14]);
    /// ```
    pub fn compute(data: &[u8]) -> [u8; 4] {
        use crc::{Crc, CRC_32_ISO_HDLC};
        const CRC_ALGO: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
        CRC_ALGO.checksum(data).to_be_bytes()
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: 0x", Self::TYPE)?;
        for val in self.fingerprint.iter() {
            write!(f, "{:02x}", val)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn fingerprint() {
        init();
        let val = [1; 4];
        let attr = Fingerprint::new(val);
        assert_eq!(attr.fingerprint(), &val);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), Fingerprint::TYPE);
        let mapped2 = Fingerprint::try_from(&raw).unwrap();
        assert_eq!(mapped2.fingerprint(), &val);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            Fingerprint::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::Truncated {
                expected: 4,
                actual: 3
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Fingerprint::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
