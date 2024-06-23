// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;

use crate::message::{StunParseError, StunWriteError};

use super::{Attribute, AttributeType, RawAttribute};

/// The Realm [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Realm {
    realm: String,
}

impl Attribute for Realm {
    const TYPE: AttributeType = AttributeType(0x0014);

    fn length(&self) -> u16 {
        self.realm.len() as u16
    }
}
impl From<Realm> for RawAttribute {
    fn from(value: Realm) -> RawAttribute {
        RawAttribute::new(Realm::TYPE, value.realm.as_bytes())
    }
}
impl TryFrom<&RawAttribute> for Realm {
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

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn realm() {
        init();
        let attr = Realm::new("realm").unwrap();
        assert_eq!(attr.realm(), "realm");
        let raw: RawAttribute = attr.into();
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
}
