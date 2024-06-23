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

/// The username [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Username {
    user: String,
}
impl Attribute for Username {
    const TYPE: AttributeType = AttributeType(0x0006);

    fn length(&self) -> u16 {
        self.user.len() as u16
    }
}
impl<'a> From<&'a Username> for RawAttribute<'a> {
    fn from(value: &'a Username) -> RawAttribute<'a> {
        RawAttribute::new(Username::TYPE, value.user.as_bytes())
    }
}
impl<'a> TryFrom<&RawAttribute<'a>> for Username {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..=513)?;
        Ok(Self {
            user: std::str::from_utf8(&raw.value)
                .map_err(|_| StunParseError::InvalidAttributeData)?
                .to_owned(),
        })
    }
}

impl Username {
    /// Create a new [`Username`] [`Attribute`]
    ///
    /// # Errors
    ///
    /// - When the length of the username is longer than allowed in a STUN
    /// [`Message`](crate::message::Message)
    /// - TODO: If converting through SASLPrep fails
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let username = Username::new ("user").unwrap();
    /// assert_eq!(username.username(), "user");
    /// ```
    pub fn new(user: &str) -> Result<Self, StunWriteError> {
        if user.len() > 513 {
            return Err(StunWriteError::TooLarge {
                expected: 513,
                actual: user.len(),
            });
        }
        // TODO: SASLPrep RFC4013 requirements
        Ok(Self {
            user: user.to_owned(),
        })
    }

    /// The username stored in a [`Username`] [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let username = Username::new ("user").unwrap();
    /// assert_eq!(username.username(), "user");
    /// ```
    pub fn username(&self) -> &str {
        &self.user
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: '{}'", Self::TYPE, self.user)
    }
}

/// The Userhash [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Userhash {
    hash: [u8; 32],
}

impl Attribute for Userhash {
    const TYPE: AttributeType = AttributeType(0x001E);

    fn length(&self) -> u16 {
        32
    }
}
impl<'a> From<&'a Userhash> for RawAttribute<'a> {
    fn from(value: &'a Userhash) -> RawAttribute<'a> {
        RawAttribute::new(Userhash::TYPE, &value.hash)
    }
}

impl<'a> TryFrom<&RawAttribute<'a>> for Userhash {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 32..=32)?;
        // sized checked earlier
        let hash: [u8; 32] = raw.value[..32].try_into().unwrap();
        Ok(Self { hash })
    }
}

impl Userhash {
    /// Create a new Userhash [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let value = [0;32];
    /// let user = Userhash::new(value);
    /// assert_eq!(user.hash(), &value);
    /// ```
    pub fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Retrieve the hash value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let value = [0;32];
    /// let user = Userhash::new(value);
    /// assert_eq!(user.hash(), &value);
    /// ```
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Compute the hash of a specified block of data as required by STUN
    ///
    /// # Examples
    /// ```
    /// # use stun_types::attribute::*;
    /// assert_eq!(Userhash::compute("user", "realm"), [106, 48, 41, 17, 107, 71, 170, 152, 188, 170, 50, 83, 153, 115, 61, 193, 162, 60, 213, 126, 38, 184, 27, 239, 63, 246, 83, 28, 230, 36, 226, 218]);
    /// ```
    pub fn compute(user: &str, realm: &str) -> [u8; 32] {
        let data = user.to_string() + ":" + realm;
        use sha2::{Digest, Sha256};
        let ret = Sha256::digest(data);
        ret.as_slice().try_into().unwrap()
    }
}

impl std::fmt::Display for Userhash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: 0x", Self::TYPE)?;
        for val in self.hash.iter() {
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
    fn username() {
        init();
        let s = "woohoo!";
        let user = Username::new(s).unwrap();
        assert_eq!(user.username(), s);
        assert_eq!(user.length() as usize, s.len());
        let raw = RawAttribute::from(&user);
        assert_eq!(raw.get_type(), Username::TYPE);
        let user2 = Username::try_from(&raw).unwrap();
        assert_eq!(user2.username(), s);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Username::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn username_not_utf8() {
        init();
        let attr = Username::new("user").unwrap();
        let raw = RawAttribute::from(&attr);
        let mut data = raw.to_bytes();
        data[6] = 0x88;
        assert!(matches!(
            Username::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::InvalidAttributeData)
        ));
    }

    #[test]
    fn username_new_too_large() {
        init();
        let mut large = String::new();
        for _i in 0..64 {
            large.push_str("abcdefgh");
        }
        large.push_str("ab");
        assert!(matches!(
            Username::new(&large),
            Err(StunWriteError::TooLarge {
                expected: 513,
                actual: 514
            })
        ));
    }

    #[test]
    fn userhash() {
        init();
        let hash = Userhash::compute("username", "realm1");
        let attr = Userhash::new(hash);
        assert_eq!(attr.hash(), &hash);
        assert_eq!(attr.length(), 32);
        let raw = RawAttribute::from(&attr);
        assert_eq!(raw.get_type(), Userhash::TYPE);
        let mapped2 = Userhash::try_from(&raw).unwrap();
        assert_eq!(mapped2.hash(), &hash);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            Userhash::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::Truncated {
                expected: 32,
                actual: 31
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Userhash::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
