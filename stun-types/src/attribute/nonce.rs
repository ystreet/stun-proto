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

/// The Nonce [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
    nonce: String,
}

impl Attribute for Nonce {
    const TYPE: AttributeType = AttributeType(0x0015);

    fn length(&self) -> u16 {
        self.nonce.len() as u16
    }
}
impl From<Nonce> for RawAttribute {
    fn from(value: Nonce) -> RawAttribute {
        RawAttribute::new(Nonce::TYPE, value.nonce.as_bytes())
    }
}
impl TryFrom<&RawAttribute> for Nonce {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..=763)?;
        Ok(Self {
            nonce: std::str::from_utf8(&raw.value)
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

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", Self::TYPE, self.nonce)
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
    fn nonce() {
        init();
        let attr = Nonce::new("nonce").unwrap();
        assert_eq!(attr.nonce(), "nonce");
        let raw: RawAttribute = attr.into();
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
}
