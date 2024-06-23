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

/// The Software [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Software {
    software: String,
}
impl Attribute for Software {
    const TYPE: AttributeType = AttributeType(0x8022);

    fn length(&self) -> u16 {
        self.software.len() as u16
    }
}
impl<'a> From<&'a Software> for RawAttribute<'a> {
    fn from(value: &'a Software) -> RawAttribute<'a> {
        RawAttribute::new(Software::TYPE, value.software.as_bytes())
    }
}
impl<'a> TryFrom<&RawAttribute<'a>> for Software {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..=763)?;
        Ok(Self {
            software: std::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidAttributeData)?
                .to_owned(),
        })
    }
}

impl Software {
    /// Create a new unknown attributes [`Attribute`]
    ///
    /// # Errors
    ///
    /// If the length of the provided string is too long for the [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let software = Software::new("stun-types 0.1").unwrap();
    /// assert_eq!(software.software(), "stun-types 0.1");
    /// ```
    pub fn new(software: &str) -> Result<Self, StunWriteError> {
        // TODO: should only allow 128 characters
        if software.len() > 763 {
            return Err(StunWriteError::TooLarge {
                expected: 763,
                actual: software.len(),
            });
        }
        Ok(Self {
            software: software.to_owned(),
        })
    }

    /// The value of the software field
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let software = Software::new("stun-types 0.1").unwrap();
    /// assert_eq!(software.software(), "stun-types 0.1");
    /// ```
    pub fn software(&self) -> &str {
        &self.software
    }
}

impl std::fmt::Display for Software {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: '{}'", Software::TYPE, self.software)
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
    fn software() {
        init();
        let software = Software::new("software").unwrap();
        assert_eq!(software.software(), "software");
        assert_eq!(software.length() as usize, "software".len());
        let raw = RawAttribute::from(&software);
        assert_eq!(raw.get_type(), Software::TYPE);
        let software2 = Software::try_from(&raw).unwrap();
        assert_eq!(software2.software(), "software");
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Software::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn software_not_utf8() {
        init();
        let attr = Software::new("software").unwrap();
        let raw = RawAttribute::from(&attr);
        let mut data = raw.to_bytes();
        data[6] = 0x88;
        assert!(matches!(
            Software::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::InvalidAttributeData)
        ));
    }

    #[test]
    fn software_new_too_large() {
        init();
        let mut large = String::new();
        for _i in 0..95 {
            large.push_str("abcdefgh");
        }
        large.push_str("abcd");
        assert!(matches!(
            Software::new(&large),
            Err(StunWriteError::TooLarge {
                expected: 763,
                actual: 764
            })
        ));
    }
}
