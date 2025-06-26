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

use super::{
    Attribute, AttributeFromRaw, AttributeStaticType, AttributeType, AttributeWrite,
    AttributeWriteExt, RawAttribute,
};

/// The Priority [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Priority {
    priority: u32,
}

impl AttributeStaticType for Priority {
    const TYPE: AttributeType = AttributeType(0x0024);
}
impl Attribute for Priority {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        4
    }
}
impl AttributeWrite for Priority {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut buf = [0; 4];
        BigEndian::write_u32(&mut buf[0..4], self.priority);
        RawAttribute::new(Priority::TYPE, &buf).into_owned()
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        BigEndian::write_u32(&mut dest[4..8], self.priority);
    }
}

impl AttributeFromRaw<'_> for Priority {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for Priority {
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

impl AttributeStaticType for UseCandidate {
    const TYPE: AttributeType = AttributeType(0x0025);
}
impl Attribute for UseCandidate {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        0
    }
}
impl AttributeWrite for UseCandidate {
    fn to_raw(&self) -> RawAttribute<'_> {
        static BUF: [u8; 0] = [0; 0];
        RawAttribute::new(UseCandidate::TYPE, &BUF)
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
    }
}

impl AttributeFromRaw<'_> for UseCandidate {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for UseCandidate {
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

impl AttributeStaticType for IceControlled {
    const TYPE: AttributeType = AttributeType(0x8029);
}
impl Attribute for IceControlled {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        8
    }
}
impl AttributeWrite for IceControlled {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf[..8], self.tie_breaker);
        RawAttribute::new(IceControlled::TYPE, &buf).into_owned()
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        BigEndian::write_u64(&mut dest[4..12], self.tie_breaker);
    }
}

impl AttributeFromRaw<'_> for IceControlled {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for IceControlled {
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

impl AttributeStaticType for IceControlling {
    const TYPE: AttributeType = AttributeType(0x802A);
}

impl Attribute for IceControlling {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        8
    }
}

impl AttributeWrite for IceControlling {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf[..8], self.tie_breaker);
        RawAttribute::new(IceControlling::TYPE, &buf).into_owned()
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        BigEndian::write_u64(&mut dest[4..12], self.tie_breaker);
    }
}

impl AttributeFromRaw<'_> for IceControlling {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for IceControlling {
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
    use tracing::trace;

    #[test]
    fn priority() {
        let _log = crate::tests::test_init_log();
        let val = 100;
        let priority = Priority::new(val);
        trace!("{priority}");
        assert_eq!(priority.priority(), val);
        assert_eq!(priority.length(), 4);
        let raw = RawAttribute::from(&priority);
        trace!("{raw}");
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
        let _log = crate::tests::test_init_log();
        let use_candidate = UseCandidate::default();
        trace!("{use_candidate}");
        assert_eq!(use_candidate.length(), 0);
        let raw = RawAttribute::from(&use_candidate);
        trace!("{raw}");
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
        let _log = crate::tests::test_init_log();
        let tb = 100;
        let attr = IceControlling::new(tb);
        trace!("{attr}");
        assert_eq!(attr.tie_breaker(), tb);
        assert_eq!(attr.length(), 8);
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
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
        let _log = crate::tests::test_init_log();
        let tb = 100;
        let attr = IceControlled::new(tb);
        trace!("{attr}");
        assert_eq!(attr.tie_breaker(), tb);
        assert_eq!(attr.length(), 8);
        let raw = RawAttribute::from(&attr);
        trace!("{raw}");
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
