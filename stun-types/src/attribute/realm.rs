// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;

use crate::message::{StunParseError, StunWriteError};

use super::{
    Attribute, AttributeExt, AttributeFromRaw, AttributeStaticType, AttributeType, AttributeWrite,
    AttributeWriteExt, RawAttribute,
};

/// The Realm [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Realm {
    realm: String,
}

impl AttributeStaticType for Realm {
    const TYPE: AttributeType = AttributeType(0x0014);
}

impl Attribute for Realm {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        self.realm.len() as u16
    }
}

impl AttributeWrite for Realm {
    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(Realm::TYPE, self.realm.as_bytes())
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        let len = self.padded_len();
        self.write_header_unchecked(dest);
        let offset = 4 + self.realm.len();
        dest[4..offset].copy_from_slice(self.realm.as_bytes());
        if len > offset {
            dest[offset..len].fill(0);
        }
    }
}

impl<'a> AttributeFromRaw<'a> for Realm {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl<'a> TryFrom<&RawAttribute<'a>> for Realm {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..=763)?;
        Ok(Self {
            realm: std::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidAttributeData)?
                .to_owned(),
        })
    }
}

impl Realm {
    /// Create a new Realm [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let realm = Realm::new("realm").unwrap();
    /// assert_eq!(realm.realm(), "realm");
    /// ```
    pub fn new(realm: &str) -> Result<Self, StunWriteError> {
        if realm.len() > 763 {
            return Err(StunWriteError::TooLarge {
                expected: 763,
                actual: realm.len(),
            });
        }
        Ok(Self {
            realm: realm.to_string(),
        })
    }

    /// Retrieve the realm value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let realm = Realm::new("realm").unwrap();
    /// assert_eq!(realm.realm(), "realm");
    /// ```
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

impl std::fmt::Display for Realm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", Self::TYPE, self.realm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};
    use tracing::trace;

    #[test]
    fn realm() {
        let _log = crate::tests::test_init_log();
        let attr = Realm::new("realm").unwrap();
        trace!("{attr}");
        assert_eq!(attr.realm(), "realm");
        assert_eq!(attr.length() as usize, "realm".len());
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
        assert_eq!(raw.get_type(), Realm::TYPE);
        let mapped2 = Realm::try_from(&raw).unwrap();
        assert_eq!(mapped2.realm(), "realm");
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Realm::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn realm_not_utf8() {
        let _log = crate::tests::test_init_log();
        let attr = Realm::new("realm").unwrap();
        let raw = RawAttribute::from(&attr);
        let mut data = raw.to_bytes();
        data[6] = 0x88;
        assert!(matches!(
            Realm::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::InvalidAttributeData)
        ));
    }

    #[test]
    fn realme_new_too_large() {
        let _log = crate::tests::test_init_log();
        let mut large = String::new();
        for _i in 0..95 {
            large.push_str("abcdefgh");
        }
        large.push_str("abcd");
        assert!(matches!(
            Realm::new(&large),
            Err(StunWriteError::TooLarge {
                expected: 763,
                actual: 764
            })
        ));
    }
}
