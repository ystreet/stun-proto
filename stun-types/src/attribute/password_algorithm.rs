// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder};

use crate::message::StunParseError;

use super::{padded_attr_len, Attribute, AttributeType, RawAttribute};

/// The hashing algorithm for the password
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAlgorithmValue {
    MD5,
    SHA256,
}

impl PasswordAlgorithmValue {
    fn len(&self) -> u16 {
        // all current algorithms have no parameter values
        0
    }

    fn write(&self, data: &mut [u8]) {
        let ty = match self {
            Self::MD5 => 0x1,
            Self::SHA256 => 0x2,
        };
        BigEndian::write_u16(&mut data[..2], ty);
        BigEndian::write_u16(&mut data[2..4], self.len());
    }

    fn read(data: &[u8]) -> Result<Self, StunParseError> {
        // checked externally that we have at least 4 bytes
        let ty = BigEndian::read_u16(&data[..2]);
        let len = BigEndian::read_u16(&data[2..4]);
        // all currently know algorithms don't ahve any extra data
        if len != 0 {
            return Err(StunParseError::TooLarge {
                expected: 4,
                actual: 4 + len as usize,
            });
        }
        Ok(match ty {
            0x1 => Self::MD5,
            0x2 => Self::SHA256,
            _ => return Err(StunParseError::InvalidAttributeData),
        })
    }
}

impl std::fmt::Display for PasswordAlgorithmValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MD5 => write!(f, "MD5"),
            Self::SHA256 => write!(f, "SHA256"),
        }
    }
}

/// The PasswordAlgorithms [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordAlgorithms {
    algorithms: Vec<PasswordAlgorithmValue>,
}

impl Attribute for PasswordAlgorithms {
    const TYPE: AttributeType = AttributeType(0x8002);

    fn length(&self) -> u16 {
        let mut len = 0;
        for algo in self.algorithms.iter() {
            len += 4 + padded_attr_len(algo.len() as usize);
        }
        len as u16
    }
}
impl From<PasswordAlgorithms> for RawAttribute {
    fn from(value: PasswordAlgorithms) -> RawAttribute {
        let len = value.length() as usize;
        let mut data = vec![0; len];
        let mut i = 0;
        for algo in value.algorithms.iter() {
            algo.write(&mut data[i..]);
            i += 4 + padded_attr_len(algo.len() as usize);
        }
        RawAttribute::new(PasswordAlgorithms::TYPE, &data)
    }
}
impl TryFrom<&RawAttribute> for PasswordAlgorithms {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..)?;
        if raw.value.len() % 4 != 0 {
            return Err(StunParseError::InvalidAttributeData);
        }
        let mut i = 0;
        let mut algorithms = vec![];
        while i < raw.value.len() {
            let algo = PasswordAlgorithmValue::read(&raw.value[i..])?;
            i += 4 + padded_attr_len(algo.len() as usize);
            algorithms.push(algo);
        }
        Ok(Self { algorithms })
    }
}

impl PasswordAlgorithms {
    /// Create a new PasswordAlgorithms [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let algorithms = PasswordAlgorithms::new(&[PasswordAlgorithmValue::MD5]);
    /// assert_eq!(algorithms.algorithms(), &[PasswordAlgorithmValue::MD5]);
    /// ```
    pub fn new(algorithms: &[PasswordAlgorithmValue]) -> Self {
        Self {
            algorithms: algorithms.to_vec(),
        }
    }

    /// Retrieve the algorithms value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let algorithms = PasswordAlgorithms::new(&[PasswordAlgorithmValue::MD5]);
    /// assert_eq!(algorithms.algorithms(), &[PasswordAlgorithmValue::MD5]);
    /// ```
    pub fn algorithms(&self) -> &[PasswordAlgorithmValue] {
        &self.algorithms
    }
}

impl std::fmt::Display for PasswordAlgorithms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: [", Self::TYPE)?;
        for (i, algo) in self.algorithms.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", algo)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

/// The PasswordAlgorithm [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordAlgorithm {
    algorithm: PasswordAlgorithmValue,
}

impl Attribute for PasswordAlgorithm {
    const TYPE: AttributeType = AttributeType(0x001D);

    fn length(&self) -> u16 {
        4 + padded_attr_len(self.algorithm.len() as usize) as u16
    }
}

impl From<PasswordAlgorithm> for RawAttribute {
    fn from(value: PasswordAlgorithm) -> RawAttribute {
        let len = value.length() as usize;
        let mut data = vec![0; len];
        value.algorithm.write(&mut data);
        RawAttribute::new(PasswordAlgorithm::TYPE, &data)
    }
}
impl TryFrom<&RawAttribute> for PasswordAlgorithm {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..)?;
        if raw.value.len() % 4 != 0 {
            return Err(StunParseError::InvalidAttributeData);
        }
        let algorithm = PasswordAlgorithmValue::read(&raw.value)?;
        Ok(Self { algorithm })
    }
}

impl PasswordAlgorithm {
    /// Create a new PasswordAlgorithm [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let algorithm = PasswordAlgorithm::new(PasswordAlgorithmValue::MD5);
    /// assert_eq!(algorithm.algorithm(), PasswordAlgorithmValue::MD5);
    /// ```
    pub fn new(algorithm: PasswordAlgorithmValue) -> Self {
        Self { algorithm }
    }

    /// Retrieve the algorithm value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let algorithm = PasswordAlgorithm::new(PasswordAlgorithmValue::MD5);
    /// assert_eq!(algorithm.algorithm(), PasswordAlgorithmValue::MD5);
    /// ```
    pub fn algorithm(&self) -> PasswordAlgorithmValue {
        self.algorithm
    }
}

impl std::fmt::Display for PasswordAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", Self::TYPE, self.algorithm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn password_algorithms() {
        init();
        let vals = [PasswordAlgorithmValue::MD5, PasswordAlgorithmValue::SHA256];
        let attr = PasswordAlgorithms::new(&vals);
        assert_eq!(attr.algorithms(), &vals);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), PasswordAlgorithms::TYPE);
        let mapped2 = PasswordAlgorithms::try_from(&raw).unwrap();
        assert_eq!(mapped2.algorithms(), &vals);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            PasswordAlgorithms::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn password_algorithm() {
        init();
        let val = PasswordAlgorithmValue::SHA256;
        let attr = PasswordAlgorithm::new(val);
        assert_eq!(attr.algorithm(), val);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), PasswordAlgorithm::TYPE);
        let mapped2 = PasswordAlgorithm::try_from(&raw).unwrap();
        assert_eq!(mapped2.algorithm(), val);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            PasswordAlgorithm::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn password_algorithm_value_too_large() {
        init();
        let val = PasswordAlgorithmValue::SHA256;
        let attr = PasswordAlgorithm::new(val);
        let raw: RawAttribute = attr.into();
        let mut data = raw.to_bytes();
        data[7] = 100;
        assert!(matches!(
            PasswordAlgorithm::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::TooLarge {
                expected: 4,
                actual: 104
            })
        ));
    }

    #[test]
    fn password_algorithm_value_unknown() {
        init();
        let val = PasswordAlgorithmValue::SHA256;
        let attr = PasswordAlgorithm::new(val);
        let raw: RawAttribute = attr.into();
        let mut data = raw.to_bytes();
        data[5] = 0x80;
        assert!(matches!(
            PasswordAlgorithm::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::InvalidAttributeData)
        ));
    }
}
