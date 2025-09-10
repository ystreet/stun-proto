// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use alloc::vec::Vec;
use core::convert::TryFrom;

use crate::message::{IntegrityKey, StunParseError, StunWriteError};

use super::{
    Attribute, AttributeFromRaw, AttributeStaticType, AttributeType, AttributeWrite,
    AttributeWriteExt, RawAttribute,
};

use tracing::{debug, error};

/// The MessageIntegrity [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageIntegrity {
    hmac: [u8; 20],
}

impl AttributeStaticType for MessageIntegrity {
    const TYPE: AttributeType = AttributeType(0x0008);
}

impl Attribute for MessageIntegrity {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        20
    }
}

impl AttributeWrite for MessageIntegrity {
    fn to_raw(&self) -> RawAttribute<'_> {
        RawAttribute::new(MessageIntegrity::TYPE, &self.hmac)
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        dest[4..4 + self.hmac.len()].copy_from_slice(&self.hmac);
    }
}

impl AttributeFromRaw<'_> for MessageIntegrity {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for MessageIntegrity {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 20..=20)?;
        // sized checked earlier
        let hmac: [u8; 20] = (&*raw.value).try_into().unwrap();
        Ok(Self { hmac })
    }
}

impl MessageIntegrity {
    /// Create a new MessageIntegrity [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let hmac = [0;20];
    /// let integrity = MessageIntegrity::new(hmac);
    /// assert_eq!(integrity.hmac(), &hmac);
    /// ```
    pub fn new(hmac: [u8; 20]) -> Self {
        Self { hmac }
    }

    /// Retrieve the value of the hmac
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let hmac = [0; 20];
    /// let integrity = MessageIntegrity::new(hmac);
    /// assert_eq!(integrity.hmac(), &hmac);
    /// ```
    pub fn hmac(&self) -> &[u8; 20] {
        &self.hmac
    }

    /// Compute the Message Integrity value of a chunk of data using a key
    ///
    /// Note: use `MessageIntegrity::verify` for the actual verification to ensure constant time
    /// checks of the values to defeat certain types of timing attacks.
    ///
    /// # Examples
    /// ```
    /// # use stun_types::attribute::*;
    /// # use stun_types::message::*;
    /// let credentials = ShortTermCredentials::new("pass".to_owned());
    /// let key = MessageIntegrityCredentials::from(credentials).make_key();
    /// let data = [10; 30];
    /// let expected = [92, 91, 148, 243, 28, 168, 16, 154, 137, 179, 250, 169, 153, 222, 37, 127, 210, 148, 222, 119];
    /// let integrity = MessageIntegrity::compute(&[&data], &key).unwrap();
    /// assert_eq!(integrity, expected);
    /// ```
    #[tracing::instrument(
        name = "MessageIntegrity::compute",
        level = "trace",
        err,
        skip(data, key)
    )]
    pub fn compute(data: &[&[u8]], key: &IntegrityKey) -> Result<[u8; 20], StunWriteError> {
        use hmac::{Hmac, Mac};
        let mut hmac =
            Hmac::<sha1::Sha1>::new_from_slice(key.as_bytes()).map_err(|_| StunWriteError::IntegrityFailed)?;
        for data in data {
            hmac.update(data);
        }
        Ok(hmac.finalize().into_bytes().into())
    }

    /// Compute the Message Integrity value of a chunk of data using a key
    ///
    /// # Examples
    /// ```
    /// # use stun_types::attribute::*;
    /// # use stun_types::message::*;
    /// let credentials = ShortTermCredentials::new("pass".to_owned());
    /// let key = MessageIntegrityCredentials::from(credentials).make_key();
    /// let data = [10; 30];
    /// let expected = [92, 91, 148, 243, 28, 168, 16, 154, 137, 179, 250, 169, 153, 222, 37, 127, 210, 148, 222, 119];
    /// assert_eq!(MessageIntegrity::verify(&[&data], &key, &expected).unwrap(), ());
    /// ```
    #[tracing::instrument(
        name = "MessageIntegrity::verify",
        level = "debug",
        skip(data, key, expected)
    )]
    pub fn verify(data: &[&[u8]], key: &IntegrityKey, expected: &[u8; 20]) -> Result<(), StunParseError> {
        use hmac::{Hmac, Mac};
        let mut hmac = Hmac::<sha1::Sha1>::new_from_slice(key.as_bytes()).map_err(|_| {
            error!("failed to create hmac from key data");
            StunParseError::InvalidAttributeData
        })?;
        for data in data {
            hmac.update(data);
        }
        hmac.verify_slice(expected).map_err(|_| {
            debug!("integrity check failed");
            StunParseError::IntegrityCheckFailed
        })
    }
}

impl core::fmt::Display for MessageIntegrity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: 0x", Self::TYPE)?;
        for val in self.hmac.iter() {
            write!(f, "{val:02x}")?;
        }
        Ok(())
    }
}

/// The MessageIntegritySha256 [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageIntegritySha256 {
    hmac: Vec<u8>,
}

impl AttributeStaticType for MessageIntegritySha256 {
    const TYPE: AttributeType = AttributeType(0x001C);
}

impl Attribute for MessageIntegritySha256 {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        self.hmac.len() as u16
    }
}

impl AttributeWrite for MessageIntegritySha256 {
    fn to_raw(&self) -> RawAttribute<'_> {
        RawAttribute::new(MessageIntegritySha256::TYPE, &self.hmac)
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        dest[4..4 + self.hmac.len()].copy_from_slice(&self.hmac);
    }
}

impl AttributeFromRaw<'_> for MessageIntegritySha256 {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for MessageIntegritySha256 {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 16..=32)?;
        if raw.value.len() % 4 != 0 {
            return Err(StunParseError::InvalidAttributeData);
        }
        Ok(Self {
            hmac: raw.value.to_vec(),
        })
    }
}

impl MessageIntegritySha256 {
    /// Create a new MessageIntegritySha256 [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let hmac = [0;20];
    /// let integrity = MessageIntegritySha256::new(&hmac).unwrap();
    /// assert_eq!(integrity.hmac(), &hmac);
    /// ```
    pub fn new(hmac: &[u8]) -> Result<Self, StunWriteError> {
        if hmac.len() < 16 {
            return Err(StunWriteError::TooSmall {
                expected: 16,
                actual: hmac.len(),
            });
        }
        if hmac.len() > 32 {
            return Err(StunWriteError::TooLarge {
                expected: 32,
                actual: hmac.len(),
            });
        }
        if hmac.len() % 4 != 0 {
            return Err(StunWriteError::IntegrityFailed);
        }
        Ok(Self {
            hmac: hmac.to_vec(),
        })
    }

    /// Retrieve the value of the hmac
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let hmac = [0; 20];
    /// let integrity = MessageIntegritySha256::new(&hmac).unwrap();
    /// assert_eq!(integrity.hmac(), &hmac);
    /// ```
    pub fn hmac(&self) -> &[u8] {
        &self.hmac
    }

    /// Compute the Message Integrity value of a chunk of data using a key
    ///
    /// Note: use `MessageIntegritySha256::verify` for the actual verification to ensure constant time
    /// checks of the values to defeat certain types of timing attacks.
    ///
    /// # Examples
    /// ```
    /// # use stun_types::attribute::*;
    /// # use stun_types::message::*;
    /// let credentials = ShortTermCredentials::new("pass".to_owned());
    /// let key = MessageIntegrityCredentials::from(credentials).make_key();
    /// let data = [10; 30];
    /// let expected = [16, 175, 53, 195, 18, 50, 153, 148, 7, 247, 27, 185, 195, 171, 22, 197, 22, 180, 244, 67, 190, 185, 71, 34, 150, 194, 108, 18, 75, 94, 221, 185];
    /// let integrity = MessageIntegritySha256::compute(&[&data], &key).unwrap();
    /// assert_eq!(integrity, expected);
    /// ```
    #[tracing::instrument(
        name = "MessageIntegritySha256::compute",
        level = "trace",
        err,
        skip(data, key)
    )]
    pub fn compute(data: &[&[u8]], key: &IntegrityKey) -> Result<[u8; 32], StunWriteError> {
        use hmac::{Hmac, Mac};
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes())
            .map_err(|_| StunWriteError::IntegrityFailed)?;
        for data in data {
            hmac.update(data);
        }
        let ret = hmac.finalize().into_bytes();
        Ok(ret.into())
    }

    /// Compute the Message Integrity value of a chunk of data using a key
    ///
    /// # Examples
    /// ```
    /// # use stun_types::attribute::*;
    /// # use stun_types::message::*;
    /// let credentials = ShortTermCredentials::new("pass".to_owned());
    /// let key = MessageIntegrityCredentials::from(credentials).make_key();
    /// let data = [10; 30];
    /// let expected = [16, 175, 53, 195, 18, 50, 153, 148, 7, 247, 27, 185, 195, 171, 22, 197, 22, 180, 244, 67, 190, 185, 71, 34, 150, 194, 108, 18, 75, 94, 221, 185];
    /// assert_eq!(MessageIntegritySha256::verify(&[&data], &key, &expected).unwrap(), ());
    /// ```
    #[tracing::instrument(
        name = "MessageIntegritySha256::verify",
        level = "debug",
        skip(data, key, expected)
    )]
    pub fn verify(data: &[&[u8]], key: &IntegrityKey, expected: &[u8]) -> Result<(), StunParseError> {
        use hmac::{Hmac, Mac};
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes()).map_err(|_| {
            error!("failed to create hmac from key data");
            StunParseError::InvalidAttributeData
        })?;
        for data in data {
            hmac.update(data);
        }
        hmac.verify_truncated_left(expected).map_err(|_| {
            debug!("integrity check failed");
            StunParseError::IntegrityCheckFailed
        })
    }
}

impl core::fmt::Display for MessageIntegritySha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: 0x", Self::TYPE)?;
        for val in self.hmac.iter() {
            write!(f, "{val:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};
    use tracing::trace;

    #[test]
    fn message_integrity() {
        let _log = crate::tests::test_init_log();
        let val = [1; 20];
        let attr = MessageIntegrity::new(val);
        trace!("{attr}");
        assert_eq!(attr.hmac(), &val);
        assert_eq!(attr.length(), 20);
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
        assert_eq!(raw.get_type(), MessageIntegrity::TYPE);
        let mapped2 = MessageIntegrity::try_from(&raw).unwrap();
        assert_eq!(mapped2.hmac(), &val);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            MessageIntegrity::try_from(
                &RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()
            ),
            Err(StunParseError::Truncated {
                expected: 20,
                actual: 19
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            MessageIntegrity::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn message_integrity_sha256() {
        let _log = crate::tests::test_init_log();
        let val = [1; 32];
        let attr = MessageIntegritySha256::new(&val).unwrap();
        trace!("{attr}");
        assert_eq!(attr.hmac(), &val);
        assert_eq!(attr.length(), 32);
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
        assert_eq!(raw.get_type(), MessageIntegritySha256::TYPE);
        let mapped2 = MessageIntegritySha256::try_from(&raw).unwrap();
        assert_eq!(mapped2.hmac(), &val);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            MessageIntegritySha256::try_from(
                &RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()
            ),
            Err(StunParseError::InvalidAttributeData)
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            MessageIntegritySha256::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn message_integrity_sha256_new_too_large() {
        let _log = crate::tests::test_init_log();
        let val = [1; 33];
        assert!(matches!(
            MessageIntegritySha256::new(&val),
            Err(StunWriteError::TooLarge {
                expected: 32,
                actual: 33
            })
        ));
    }

    #[test]
    fn message_integrity_sha256_new_too_small() {
        let _log = crate::tests::test_init_log();
        let val = [1; 15];
        assert!(matches!(
            MessageIntegritySha256::new(&val),
            Err(StunWriteError::TooSmall {
                expected: 16,
                actual: 15
            })
        ));
    }

    #[test]
    fn message_integrity_sha256_new_not_multiple_of_4() {
        let _log = crate::tests::test_init_log();
        let val = [1; 19];
        assert!(matches!(
            MessageIntegritySha256::new(&val),
            Err(StunWriteError::IntegrityFailed)
        ));
    }
}
