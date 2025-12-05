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

/// The username [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Username {
    user: String,
}

impl AttributeStaticType for Username {
    const TYPE: AttributeType = AttributeType(0x0006);
}

impl Attribute for Username {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        self.user.len() as u16
    }
}

impl AttributeWrite for Username {
    fn to_raw(&self) -> RawAttribute<'_> {
        RawAttribute::new(Username::TYPE, self.user.as_bytes())
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        let len = self.padded_len();
        self.write_header_unchecked(dest);
        let offset = 4 + self.user.len();
        dest[4..offset].copy_from_slice(self.user.as_bytes());
        if len > offset {
            dest[offset..len].fill(0);
        }
    }
}

impl AttributeFromRaw<'_> for Username {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for Username {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..=513)?;
        Ok(Self {
            user: core::str::from_utf8(&raw.value)
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
    ///   [`Message`](crate::message::Message)
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

impl core::fmt::Display for Username {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: '{}'", Self::TYPE, self.user)
    }
}

/// The Userhash [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Userhash {
    hash: [u8; 32],
}

impl AttributeStaticType for Userhash {
    const TYPE: AttributeType = AttributeType(0x001E);
}

impl Attribute for Userhash {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        32
    }
}

impl AttributeWrite for Userhash {
    fn to_raw(&self) -> RawAttribute<'_> {
        RawAttribute::new(Userhash::TYPE, &self.hash)
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        dest[4..4 + self.hash.len()].copy_from_slice(&self.hash);
    }
}

impl AttributeFromRaw<'_> for Userhash {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for Userhash {
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
        #[allow(deprecated)]
        {
            ret.as_slice().try_into().unwrap()
        }
    }
}

impl core::fmt::Display for Userhash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: 0x", Self::TYPE)?;
        for val in self.hash.iter() {
            write!(f, "{val:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use byteorder::{BigEndian, ByteOrder};
    use tracing::trace;

    #[test]
    fn username() {
        let _log = crate::tests::test_init_log();
        let s = "woohoo!";
        let user = Username::new(s).unwrap();
        trace!("{user}");
        assert_eq!(user.username(), s);
        assert_eq!(user.length() as usize, s.len());
    }

    #[test]
    fn username_raw() {
        let _log = crate::tests::test_init_log();
        let s = "woohoo!";
        let user = Username::new(s).unwrap();
        let raw = RawAttribute::from(&user);
        trace!("{raw}");
        assert_eq!(raw.get_type(), Username::TYPE);
        let user2 = Username::try_from(&raw).unwrap();
        assert_eq!(user2.username(), s);
    }

    #[test]
    fn username_raw_wrong_type() {
        let _log = crate::tests::test_init_log();
        let s = "woohoo!";
        let user = Username::new(s).unwrap();
        let raw = RawAttribute::from(&user);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Username::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn username_write_into() {
        let _log = crate::tests::test_init_log();
        let s = "woohoo!";
        let user = Username::new(s).unwrap();
        let raw = RawAttribute::from(&user);

        let mut dest = vec![0; raw.padded_len()];
        user.write_into(&mut dest).unwrap();
        let raw = RawAttribute::from_bytes(&dest).unwrap();
        let user2 = Username::try_from(&raw).unwrap();
        assert_eq!(user2.username(), s);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn username_write_into_unchecked() {
        let _log = crate::tests::test_init_log();
        let s = "woohoo!";
        let user = Username::new(s).unwrap();
        let raw = RawAttribute::from(&user);

        let mut dest = vec![0; raw.padded_len() - 1];
        user.write_into_unchecked(&mut dest);
    }

    #[test]
    fn username_not_utf8() {
        let _log = crate::tests::test_init_log();
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
        let _log = crate::tests::test_init_log();
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
        let _log = crate::tests::test_init_log();
        let hash = Userhash::compute("username", "realm1");
        let attr = Userhash::new(hash);
        trace!("{attr}");
        assert_eq!(attr.hash(), &hash);
        assert_eq!(attr.length(), 32);
    }

    #[test]
    fn userhash_raw() {
        let _log = crate::tests::test_init_log();
        let hash = Userhash::compute("username", "realm1");
        let attr = Userhash::new(hash);
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
        assert_eq!(raw.get_type(), Userhash::TYPE);
        let mapped2 = Userhash::try_from(&raw).unwrap();
        assert_eq!(mapped2.hash(), &hash);
    }

    #[test]
    fn userhash_raw_short() {
        let _log = crate::tests::test_init_log();
        let hash = Userhash::compute("username", "realm1");
        let attr = Userhash::new(hash);
        let raw = RawAttribute::from(&attr);
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
    }

    #[test]
    fn userhash_raw_wrong_type() {
        let _log = crate::tests::test_init_log();
        let hash = Userhash::compute("username", "realm1");
        let attr = Userhash::new(hash);
        let raw = RawAttribute::from(&attr);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Userhash::from_raw_ref(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn userhash_write_into() {
        let _log = crate::tests::test_init_log();
        let hash = Userhash::compute("username", "realm1");
        let attr = Userhash::new(hash);
        let raw = RawAttribute::from(&attr);

        let mut dest = vec![0; raw.padded_len()];
        attr.write_into(&mut dest).unwrap();
        let raw = RawAttribute::from_bytes(&dest).unwrap();
        let hash2 = Userhash::try_from(&raw).unwrap();
        assert_eq!(hash2.hash(), &hash);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn userhash_write_into_unchecked() {
        let _log = crate::tests::test_init_log();
        let hash = Userhash::compute("username", "realm1");
        let attr = Userhash::new(hash);
        let raw = RawAttribute::from(&attr);

        let mut dest = vec![0; raw.padded_len() - 1];
        attr.write_into_unchecked(&mut dest);
    }
}
