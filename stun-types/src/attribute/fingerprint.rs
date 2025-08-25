// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::convert::TryFrom;

use crate::message::StunParseError;

use super::{
    Attribute, AttributeFromRaw, AttributeStaticType, AttributeType, AttributeWrite,
    AttributeWriteExt, RawAttribute,
};

/// The Fingerprint [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    fingerprint: [u8; 4],
}

impl AttributeStaticType for Fingerprint {
    const TYPE: AttributeType = AttributeType(0x8028);
}

impl Attribute for Fingerprint {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        4
    }
}

impl AttributeWrite for Fingerprint {
    fn to_raw(&self) -> RawAttribute<'_> {
        let buf = bytewise_xor!(4, self.fingerprint, Fingerprint::XOR_CONSTANT, 0);
        RawAttribute::new(Fingerprint::TYPE, &buf).into_owned()
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        let offset = self.write_header_unchecked(dest);
        let buf = bytewise_xor!(4, self.fingerprint, Fingerprint::XOR_CONSTANT, 0);
        dest[offset..offset + 4].copy_from_slice(&buf);
    }
}

impl AttributeFromRaw<'_> for Fingerprint {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for Fingerprint {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..=4)?;
        // sized checked earlier
        let boxed: [u8; 4] = (&*raw.value).try_into().unwrap();
        let fingerprint = bytewise_xor!(4, boxed, Fingerprint::XOR_CONSTANT, 0);
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

impl core::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: 0x", Self::TYPE)?;
        for val in self.fingerprint.iter() {
            write!(f, "{val:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::attribute::AttributeExt;

    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use byteorder::{BigEndian, ByteOrder};
    use tracing::trace;

    #[test]
    fn fingerprint() {
        let _log = crate::tests::test_init_log();
        let val = [1; 4];
        let attr = Fingerprint::new(val);
        trace!("{attr}");
        assert_eq!(attr.fingerprint(), &val);
        assert_eq!(attr.length(), 4);
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
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
        let mut data: Vec<_> = raw.clone().into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Fingerprint::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));

        let mut dest = vec![0; raw.padded_len()];
        attr.write_into(&mut dest).unwrap();
        let raw = RawAttribute::from_bytes(&dest).unwrap();
        let attr2 = Fingerprint::try_from(&raw).unwrap();
        assert_eq!(attr2.fingerprint(), &val);
    }
}
