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

use crate::message::{StunParseError, StunWriteError};

use super::{
    Attribute, AttributeExt, AttributeFromRaw, AttributeStaticType, AttributeType, AttributeWrite,
    AttributeWriteExt, RawAttribute,
};

/// The Nonce [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
    nonce: String,
}

impl AttributeStaticType for Nonce {
    const TYPE: AttributeType = AttributeType(0x0015);
}

impl Attribute for Nonce {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        self.nonce.len() as u16
    }
}

impl AttributeWrite for Nonce {
    fn to_raw(&self) -> RawAttribute<'_> {
        RawAttribute::new(Nonce::TYPE, self.nonce.as_bytes())
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        let len = self.padded_len();
        self.write_header_unchecked(dest);
        let offset = 4 + self.nonce.len();
        dest[4..offset].copy_from_slice(self.nonce.as_bytes());
        if len > offset {
            dest[offset..len].fill(0);
        }
    }
}

impl AttributeFromRaw<'_> for Nonce {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for Nonce {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..=763)?;
        Ok(Self {
            nonce: core::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidAttributeData)?
                .to_owned(),
        })
    }
}

impl Nonce {
    /// Create a new Nonce [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let nonce = Nonce::new("nonce").unwrap();
    /// assert_eq!(nonce.nonce(), "nonce");
    /// ```
    pub fn new(nonce: &str) -> Result<Self, StunWriteError> {
        if nonce.len() > 763 {
            return Err(StunWriteError::TooLarge {
                expected: 763,
                actual: nonce.len(),
            });
        }
        Ok(Self {
            nonce: nonce.to_string(),
        })
    }

    /// Retrieve the nonce value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let nonce = Nonce::new("nonce").unwrap();
    /// assert_eq!(nonce.nonce(), "nonce");
    /// ```
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

impl core::fmt::Display for Nonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", Self::TYPE, self.nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use byteorder::{BigEndian, ByteOrder};
    use tracing::trace;

    #[test]
    fn nonce() {
        let _log = crate::tests::test_init_log();
        let attr = Nonce::new("nonce").unwrap();
        trace!("{attr}");
        assert_eq!(attr.nonce(), "nonce");
        assert_eq!(attr.length() as usize, "nonce".len());
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
        assert_eq!(raw.get_type(), Nonce::TYPE);
        let mapped2 = Nonce::try_from(&raw).unwrap();
        assert_eq!(mapped2.nonce(), "nonce");
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Nonce::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn nonce_not_utf8() {
        let _log = crate::tests::test_init_log();
        let attr = Nonce::new("nonce").unwrap();
        let raw = RawAttribute::from(&attr);
        let mut data = raw.to_bytes();
        data[6] = 0x88;
        assert!(matches!(
            Nonce::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::InvalidAttributeData)
        ));
    }

    #[test]
    fn nonce_new_too_large() {
        let _log = crate::tests::test_init_log();
        let mut large = String::new();
        for _i in 0..95 {
            large.push_str("abcdefgh");
        }
        large.push_str("abcd");
        assert!(matches!(
            Nonce::new(&large),
            Err(StunWriteError::TooLarge {
                expected: 763,
                actual: 764
            })
        ));
    }
}
