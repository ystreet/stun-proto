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

use super::{Attribute, AttributeType, RawAttribute};

/// The Priority [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Priority {
    priority: u32,
}

impl Attribute for Priority {
    const TYPE: AttributeType = AttributeType(0x0024);

    fn length(&self) -> u16 {
        4
    }
}
impl From<Priority> for RawAttribute {
    fn from(value: Priority) -> RawAttribute {
        let mut buf = [0; 4];
        BigEndian::write_u32(&mut buf[0..4], value.priority);
        RawAttribute::new(Priority::TYPE, &buf)
    }
}
impl TryFrom<&RawAttribute> for Priority {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..=4)?;
        Ok(Self {
            priority: BigEndian::read_u32(&raw.value[..4]),
        })
    }
}

impl Priority {
    /// Create a new Priority [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let priority = Priority::new(1234);
    /// assert_eq!(priority.priority(), 1234);
    /// ```
    pub fn new(priority: u32) -> Self {
        Self { priority }
    }

    /// Retrieve the priority value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let priority = Priority::new(1234);
    /// assert_eq!(priority.priority(), 1234);
    /// ```
    pub fn priority(&self) -> u32 {
        self.priority
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", Self::TYPE, self.priority)
    }
}

/// The UseCandidate [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseCandidate {}

impl Attribute for UseCandidate {
    const TYPE: AttributeType = AttributeType(0x0025);

    fn length(&self) -> u16 {
        0
    }
}
impl From<UseCandidate> for RawAttribute {
    fn from(_value: UseCandidate) -> RawAttribute {
        let buf = [0; 0];
        RawAttribute::new(UseCandidate::TYPE, &buf)
    }
}
impl TryFrom<&RawAttribute> for UseCandidate {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 0..=0)?;
        Ok(Self {})
    }
}

impl Default for UseCandidate {
    fn default() -> Self {
        UseCandidate::new()
    }
}

impl UseCandidate {
    /// Create a new UseCandidate [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let _use_candidate = UseCandidate::new();
    /// ```
    pub fn new() -> Self {
        Self {}
    }
}

impl std::fmt::Display for UseCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Self::TYPE)
    }
}

/// The IceControlled [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceControlled {
    tie_breaker: u64,
}

impl Attribute for IceControlled {
    const TYPE: AttributeType = AttributeType(0x8029);

    fn length(&self) -> u16 {
        8
    }
}
impl From<IceControlled> for RawAttribute {
    fn from(value: IceControlled) -> RawAttribute {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf[..8], value.tie_breaker);
        RawAttribute::new(IceControlled::TYPE, &buf)
    }
}
impl TryFrom<&RawAttribute> for IceControlled {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 8..=8)?;
        Ok(Self {
            tie_breaker: BigEndian::read_u64(&raw.value),
        })
    }
}

impl IceControlled {
    /// Create a new IceControlled [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let ice_controlled = IceControlled::new(1234);
    /// assert_eq!(ice_controlled.tie_breaker(), 1234);
    /// ```
    pub fn new(tie_breaker: u64) -> Self {
        Self { tie_breaker }
    }

    /// Retrieve the tie breaker value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let ice_controlled = IceControlled::new(1234);
    /// assert_eq!(ice_controlled.tie_breaker(), 1234);
    /// ```
    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }
}

impl std::fmt::Display for IceControlled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Self::TYPE)
    }
}

/// The IceControlling [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceControlling {
    tie_breaker: u64,
}

impl Attribute for IceControlling {
    const TYPE: AttributeType = AttributeType(0x802A);

    fn length(&self) -> u16 {
        8
    }
}
impl From<IceControlling> for RawAttribute {
    fn from(value: IceControlling) -> RawAttribute {
        let mut buf = [0; 8];

        BigEndian::write_u64(&mut buf[..8], value.tie_breaker);
        RawAttribute::new(IceControlling::TYPE, &buf)
    }
}
impl TryFrom<&RawAttribute> for IceControlling {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 8..=8)?;
        Ok(Self {
            tie_breaker: BigEndian::read_u64(&raw.value),
        })
    }
}

impl IceControlling {
    /// Create a new IceControlling [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let ice_controlling = IceControlling::new(1234);
    /// assert_eq!(ice_controlling.tie_breaker(), 1234);
    /// ```
    pub fn new(tie_breaker: u64) -> Self {
        Self { tie_breaker }
    }

    /// Create a new IceControlling [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let ice_controlling = IceControlling::new(1234);
    /// assert_eq!(ice_controlling.tie_breaker(), 1234);
    /// ```
    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }
}

impl std::fmt::Display for IceControlling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Self::TYPE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn priority() {
        init();
        let val = 100;
        let priority = Priority::new(val);
        assert_eq!(priority.priority(), val);
        let raw: RawAttribute = priority.into();
        assert_eq!(raw.get_type(), Priority::TYPE);
        let mapped2 = Priority::try_from(&raw).unwrap();
        assert_eq!(mapped2.priority(), val);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            Priority::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::Truncated {
                expected: 4,
                actual: 3
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Priority::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn use_candidate() {
        init();
        let use_candidate = UseCandidate::new();
        assert_eq!(use_candidate.length(), 0);
        let raw: RawAttribute = use_candidate.into();
        assert_eq!(raw.get_type(), UseCandidate::TYPE);
        let _mapped2 = UseCandidate::try_from(&raw).unwrap();
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            UseCandidate::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn ice_controlling() {
        init();
        let tb = 100;
        let attr = IceControlling::new(tb);
        assert_eq!(attr.tie_breaker(), tb);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), IceControlling::TYPE);
        let mapped2 = IceControlling::try_from(&raw).unwrap();
        assert_eq!(mapped2.tie_breaker(), tb);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            IceControlling::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::Truncated {
                expected: 8,
                actual: 7
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            IceControlling::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn ice_controlled() {
        init();
        let tb = 100;
        let attr = IceControlled::new(tb);
        assert_eq!(attr.tie_breaker(), tb);
        let raw: RawAttribute = attr.into();
        assert_eq!(raw.get_type(), IceControlled::TYPE);
        let mapped2 = IceControlled::try_from(&raw).unwrap();
        assert_eq!(mapped2.tie_breaker(), tb);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            IceControlled::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::Truncated {
                expected: 8,
                actual: 7
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            IceControlled::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
