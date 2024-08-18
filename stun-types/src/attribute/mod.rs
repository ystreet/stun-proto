// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN Attributes
//!
//! Provides implementations for generating, parsing and manipulating STUN attributes as specified
//! in one of [RFC8489], [RFC5389], or [RFC3489].
//!
//! [RFC8489]: https://tools.ietf.org/html/rfc8489
//! [RFC5389]: https://tools.ietf.org/html/rfc5389
//! [RFC3489]: https://tools.ietf.org/html/rfc3489
//!
//! # Examples
//!
//! ### Parse and write an already defined [`Attribute`]
//!
//! ```
//! # use stun_types::prelude::*;
//! use stun_types::attribute::{RawAttribute, Software};
//! let software_name = "stun-types";
//! let software = Software::new(software_name).unwrap();
//! assert_eq!(software.software(), software_name);
//!
//! let attribute_data = [
//!     0x80, 0x22, 0x00, 0x0a, // Attribute type (0x8022: Software) and length (0x000a)
//!     0x73, 0x74, 0x75, 0x6E, // s t u n
//!     0x2D, 0x74, 0x79, 0x70, // - t y p
//!     0x65, 0x73, 0x00, 0x00  // e s
//! ];
//!
//! let raw = RawAttribute::from(&software);
//! assert_eq!(raw.to_bytes(), attribute_data);
//!
//! // Can also parse data into a typed attribute as needed
//! let software = Software::from_raw(&raw).unwrap();
//! assert_eq!(software.software(), software_name);
//! ```
//!
//! ### Defining your own [`Attribute`]
//!
//! ```
//! # use stun_types::prelude::*;
//! use byteorder::{BigEndian, ByteOrder};
//! use stun_types::attribute::{Attribute, AttributeType, RawAttribute};
//! use stun_types::message::StunParseError;
//! #[derive(Debug)]
//! struct MyAttribute {
//!    value: u32,
//! }
//! impl Attribute for MyAttribute {
//!    const TYPE: AttributeType = AttributeType::new(0x8851);
//!
//!    fn length(&self) -> u16 {
//!        4
//!    }
//! }
//! impl<'a> From<&MyAttribute> for RawAttribute<'a> {
//!     fn from(value: &MyAttribute) -> RawAttribute<'a> {
//!         let mut ret = [0; 4];
//!         BigEndian::write_u32(&mut ret, value.value);
//!         RawAttribute::new(MyAttribute::TYPE, &ret).into_owned()
//!     }
//! }
//! impl<'a> TryFrom<&RawAttribute<'a>> for MyAttribute {
//!     type Error = StunParseError;
//!     fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
//!         raw.check_type_and_len(Self::TYPE, 4..=4)?;
//!         let value = BigEndian::read_u32(&raw.value);
//!         Ok(Self {
//!             value,
//!         })
//!     }
//! }
//!
//! let my_attr = MyAttribute { value: 0x4729 };
//! let raw = RawAttribute::from(&my_attr);
//!
//! let attribute_data = [
//!     0x88, 0x51, 0x00, 0x04,
//!     0x00, 0x00, 0x47, 0x29,
//! ];
//! assert_eq!(raw.to_bytes(), attribute_data);
//!
//! let my_attr = MyAttribute::from_raw(&raw).unwrap();
//! assert_eq!(my_attr.value, 0x4729);
//! ```

macro_rules! bytewise_xor {
    ($size:literal, $a:expr, $b:expr, $default:literal) => {{
        let mut arr = [$default; $size];
        for (i, item) in arr.iter_mut().enumerate() {
            *item = $a[i] ^ $b[i];
        }
        arr
    }};
}

mod address;
pub use address::{MappedSocketAddr, XorSocketAddr};
mod alternate;
pub use alternate::{AlternateDomain, AlternateServer};
mod error;
pub use error::{ErrorCode, UnknownAttributes};
mod ice;
pub use ice::{IceControlled, IceControlling, Priority, UseCandidate};
mod integrity;
pub use integrity::{MessageIntegrity, MessageIntegritySha256};
mod fingerprint;
pub use fingerprint::Fingerprint;
mod nonce;
pub use nonce::Nonce;
mod password_algorithm;
pub use password_algorithm::{PasswordAlgorithm, PasswordAlgorithmValue, PasswordAlgorithms};
mod realm;
pub use realm::Realm;
mod user;
pub use user::{Userhash, Username};
mod software;
pub use software::Software;
mod xor_addr;
pub use xor_addr::XorMappedAddress;

use crate::data::Data;
use crate::message::{StunParseError, StunWriteError};

use byteorder::{BigEndian, ByteOrder};

/// The type of an [`Attribute`] in a STUN [`Message`](crate::message::Message)
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttributeType(u16);

impl std::fmt::Display for AttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({:#x}: {})", self.0, self.0, self.name())
    }
}

impl AttributeType {
    /// Create a new AttributeType from an existing value
    ///
    /// Note: the value passed in is not encoded as in a stun message
    ///
    /// # Examples
    /// ```
    /// # use stun_types::attribute::AttributeType;
    /// assert_eq!(AttributeType::new(0x123).value(), 0x123);
    /// ```
    pub const fn new(val: u16) -> Self {
        Self(val)
    }

    /// Return the integer value of this AttributeType
    ///
    /// Note: the value returned is not encoded as in a stun message
    ///
    /// # Examples
    /// ```
    /// # use stun_types::attribute::AttributeType;
    /// assert_eq!(AttributeType::new(0x123).value(), 0x123);
    /// ```
    pub fn value(&self) -> u16 {
        self.0
    }

    /// Returns a human readable name of this `AttributeType` or "unknown"
    ///
    /// # Examples
    /// ```
    /// # use stun_types::attribute::*;
    /// assert_eq!(XorMappedAddress::TYPE.name(), "XOR-MAPPED-ADDRESS");
    /// ```
    pub fn name(self) -> &'static str {
        match self {
            AttributeType(0x0001) => "MAPPED-ADDRESS",
            Username::TYPE => "USERNAME",
            MessageIntegrity::TYPE => "MESSAGE-INTEGRITY",
            ErrorCode::TYPE => "ERROR-CODE",
            UnknownAttributes::TYPE => "UNKNOWN-ATTRIBUTES",
            Realm::TYPE => "REALM",
            Nonce::TYPE => "NONCE",
            MessageIntegritySha256::TYPE => "MESSAGE-INTEGRITY-SHA256",
            PasswordAlgorithm::TYPE => "PASSWORD-ALGORITHM",
            Userhash::TYPE => "USERHASH",
            XorMappedAddress::TYPE => "XOR-MAPPED-ADDRESS",
            PasswordAlgorithms::TYPE => "PASSWORD_ALGORITHMS",
            AlternateDomain::TYPE => "ALTERNATE-DOMAIN",
            Software::TYPE => "SOFTWARE",
            AlternateServer::TYPE => "ALTERNATE-SERVER",
            Fingerprint::TYPE => "FINGERPRINT",
            Priority::TYPE => "PRIORITY",
            UseCandidate::TYPE => "USE-CANDIDATE",
            IceControlled::TYPE => "ICE-CONTROLLED",
            IceControlling::TYPE => "ICE-CONTROLLING",
            _ => "unknown",
        }
    }

    /// Check if comprehension is required for an `AttributeType`.  All integer attribute
    /// values < 0x8000 require comprehension.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::AttributeType;
    /// assert_eq!(AttributeType::new(0x0).comprehension_required(), true);
    /// assert_eq!(AttributeType::new(0x8000).comprehension_required(), false);
    /// ```
    pub fn comprehension_required(self) -> bool {
        self.0 < 0x8000
    }
}
impl From<u16> for AttributeType {
    fn from(f: u16) -> Self {
        Self::new(f)
    }
}
impl From<AttributeType> for u16 {
    fn from(f: AttributeType) -> Self {
        f.0
    }
}

/// Structure for holding the header of a STUN attribute.  Contains the type and the length
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AttributeHeader {
    atype: AttributeType,
    length: u16,
}

impl AttributeHeader {
    fn parse(data: &[u8]) -> Result<Self, StunParseError> {
        if data.len() < 4 {
            return Err(StunParseError::Truncated {
                expected: 4,
                actual: data.len(),
            });
        }
        let ret = Self {
            atype: BigEndian::read_u16(&data[0..2]).into(),
            length: BigEndian::read_u16(&data[2..4]),
        };
        Ok(ret)
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut ret = vec![0; 4];
        self.write_into(&mut ret);
        ret
    }

    fn write_into(&self, ret: &mut [u8]) {
        BigEndian::write_u16(&mut ret[0..2], self.atype.into());
        BigEndian::write_u16(&mut ret[2..4], self.length);
    }

    /// Returns the type of the attribute
    pub fn get_type(&self) -> AttributeType {
        self.atype
    }

    /// Returns the length of the attribute
    pub fn length(&self) -> u16 {
        self.length
    }
}
impl From<AttributeHeader> for Vec<u8> {
    fn from(f: AttributeHeader) -> Self {
        f.to_bytes()
    }
}
impl TryFrom<&[u8]> for AttributeHeader {
    type Error = StunParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        AttributeHeader::parse(value)
    }
}

/// A STUN attribute for use in [`Message`](crate::message::Message)s
pub trait Attribute: std::fmt::Debug {
    const TYPE: AttributeType;

    /// Retrieve the length of an `Attribute`.  This is not the padded length as stored in a
    /// `Message` and does not include the size of the attribute header.
    fn length(&self) -> u16;
}

/// Automatically implemented trait for converting from a concrete [`Attribute`] to a
/// [`RawAttribute`]
pub trait AttributeToRaw<'b>: Attribute + Into<RawAttribute<'b>>
where
    RawAttribute<'b>: for<'a> From<&'a Self>,
{
    /// Convert an `Attribute` to a `RawAttribute`
    fn to_raw(&self) -> RawAttribute<'b>;
}
impl<'b, T: Attribute + Into<RawAttribute<'b>>> AttributeToRaw<'b> for T
where
    RawAttribute<'b>: for<'a> From<&'a Self>,
{
    fn to_raw(&self) -> RawAttribute<'b>
    where
        RawAttribute<'b>: for<'a> From<&'a Self>,
    {
        self.into()
    }
}
/// Automatically implemented trait for converting to a concrete [`Attribute`] from a
/// [`RawAttribute`]
pub trait AttributeFromRaw<E>:
    Attribute + for<'a> TryFrom<&'a RawAttribute<'a>, Error = E>
{
    /// Convert an `Attribute` from a `RawAttribute`
    fn from_raw(raw: &RawAttribute) -> Result<Self, E>
    where
        Self: Sized;
}

impl<E, T: Attribute + for<'a> TryFrom<&'a RawAttribute<'a>, Error = E>> AttributeFromRaw<E> for T {
    fn from_raw(raw: &RawAttribute) -> Result<T, E> {
        Self::try_from(raw)
    }
}

fn padded_attr_len(len: usize) -> usize {
    if len % 4 == 0 {
        len
    } else {
        len + 4 - len % 4
    }
}

pub trait AttributeExt {
    /// The length in bytes of an attribute as stored in a [`Message`](crate::message::Message)
    /// including any padding and the attribute header.
    fn padded_len(&self) -> usize;
}

impl<A: Attribute> AttributeExt for A {
    fn padded_len(&self) -> usize {
        4 + padded_attr_len(self.length() as usize)
    }
}

/// The header and raw bytes of an unparsed [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttribute<'a> {
    /// The [`AttributeHeader`] of this [`RawAttribute`]
    pub header: AttributeHeader,
    /// The raw bytes of this [`RawAttribute`]
    pub value: Data<'a>,
}

macro_rules! display_attr {
    ($this:ident, $CamelType:ty, $default:ident) => {{
        if let Ok(attr) = <$CamelType>::from_raw($this) {
            format!("{}", attr)
        } else {
            $default
        }
    }};
}

impl<'a> std::fmt::Display for RawAttribute<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // try to get a more specialised display
        let malformed_str = format!(
            "{}(Malformed): len: {}, data: {:?})",
            self.get_type(),
            self.header.length(),
            self.value
        );
        let display_str = match self.get_type() {
            Username::TYPE => display_attr!(self, Username, malformed_str),
            MessageIntegrity::TYPE => display_attr!(self, MessageIntegrity, malformed_str),
            ErrorCode::TYPE => display_attr!(self, ErrorCode, malformed_str),
            UnknownAttributes::TYPE => display_attr!(self, UnknownAttributes, malformed_str),
            Realm::TYPE => display_attr!(self, Realm, malformed_str),
            Nonce::TYPE => display_attr!(self, Nonce, malformed_str),
            MessageIntegritySha256::TYPE => {
                display_attr!(self, MessageIntegritySha256, malformed_str)
            }
            PasswordAlgorithm::TYPE => display_attr!(self, PasswordAlgorithm, malformed_str),
            //UserHash::TYPE => display_attr!(self, UserHash, malformed_str),
            XorMappedAddress::TYPE => display_attr!(self, XorMappedAddress, malformed_str),
            PasswordAlgorithms::TYPE => display_attr!(self, PasswordAlgorithms, malformed_str),
            AlternateDomain::TYPE => display_attr!(self, AlternateDomain, malformed_str),
            Software::TYPE => display_attr!(self, Software, malformed_str),
            AlternateServer::TYPE => display_attr!(self, AlternateServer, malformed_str),
            Fingerprint::TYPE => display_attr!(self, Fingerprint, malformed_str),
            Priority::TYPE => display_attr!(self, Priority, malformed_str),
            UseCandidate::TYPE => display_attr!(self, UseCandidate, malformed_str),
            IceControlled::TYPE => display_attr!(self, IceControlled, malformed_str),
            IceControlling::TYPE => display_attr!(self, IceControlling, malformed_str),
            _ => format!(
                "RawAttribute (type: {:?}, len: {}, data: {:?})",
                self.header.get_type(),
                self.header.length(),
                &self.value
            ),
        };
        write!(f, "{}", display_str)
    }
}

impl<'a> RawAttribute<'a> {
    /// Create a new [`RawAttribute`]
    pub fn new(atype: AttributeType, data: &'a [u8]) -> Self {
        Self {
            header: AttributeHeader {
                atype,
                length: data.len() as u16,
            },
            value: data.into(),
        }
    }

    /// Deserialize a `RawAttribute` from bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::{RawAttribute, Attribute, AttributeType};
    /// let data = &[0, 1, 0, 2, 5, 6, 0, 0];
    /// let attr = RawAttribute::from_bytes(data).unwrap();
    /// assert_eq!(attr.get_type(), AttributeType::new(1));
    /// assert_eq!(attr.length(), 2);
    /// ```
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, StunParseError> {
        let header = AttributeHeader::parse(data)?;
        // the advertised length is larger than actual data -> error
        if header.length() > (data.len() - 4) as u16 {
            return Err(StunParseError::Truncated {
                expected: header.length() as usize,
                actual: data.len() - 4,
            });
        }
        Ok(Self {
            header,
            value: Data::Borrowed(data[4..header.length() as usize + 4].into()),
        })
    }

    /// Serialize a `RawAttribute` to bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::{RawAttribute, Attribute, AttributeType};
    /// let attr = RawAttribute::new(AttributeType::new(1), &[5, 6]);
    /// assert_eq!(attr.to_bytes(), &[0, 1, 0, 2, 5, 6, 0, 0]);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(self.padded_len());
        let mut header_bytes = [0; 4];
        self.header.write_into(&mut header_bytes);
        vec.extend(&header_bytes);
        vec.extend(&*self.value);
        let len = vec.len();
        if len % 4 != 0 {
            // pad to 4 bytes
            vec.resize(len + 4 - (len % 4), 0);
        }
        vec
    }

    /// Write this [`RawAttribute`] into a byte slice.  Returns the number of bytes written.
    pub fn write_into(&self, dest: &mut [u8]) -> Result<usize, StunWriteError> {
        let len = self.padded_len();
        if len > dest.len() {
            return Err(StunWriteError::TooSmall {
                expected: len,
                actual: dest.len(),
            });
        }
        self.header.write_into(dest);
        let mut offset = 4;
        dest[offset..offset + self.value.len()].copy_from_slice(&self.value);
        offset += self.value.len();
        if len - offset > 0 {
            dest[offset..len].fill(0);
        }
        Ok(len)
    }

    /// Returns the [`AttributeType`] of this [`RawAttribute`]
    pub fn get_type(&self) -> AttributeType {
        self.header.get_type()
    }

    /// Returns the length of this [`RawAttribute`]
    pub fn length(&self) -> u16 {
        self.value.len() as u16
    }

    /// Helper for checking that a raw attribute is of a particular type and within a certain range
    pub fn check_type_and_len(
        &self,
        atype: AttributeType,
        allowed_range: impl std::ops::RangeBounds<usize>,
    ) -> Result<(), StunParseError> {
        if self.header.get_type() != atype {
            return Err(StunParseError::WrongAttributeImplementation);
        }
        check_len(self.value.len(), allowed_range)
    }

    /// Consume this [`RawAttribute`] and return a new owned [`RawAttribute`]
    pub fn into_owned<'b>(self) -> RawAttribute<'b> {
        RawAttribute {
            header: self.header,
            value: self.value.into_owned(),
        }
    }
}

impl<'a> AttributeExt for RawAttribute<'a> {
    fn padded_len(&self) -> usize {
        4 + padded_attr_len(self.length() as usize)
    }
}

fn check_len(
    len: usize,
    allowed_range: impl std::ops::RangeBounds<usize>,
) -> Result<(), StunParseError> {
    match allowed_range.start_bound() {
        std::ops::Bound::Unbounded => (),
        std::ops::Bound::Included(start) => {
            if len < *start {
                return Err(StunParseError::Truncated {
                    expected: *start,
                    actual: len,
                });
            }
        }
        std::ops::Bound::Excluded(start) => {
            if len <= *start {
                return Err(StunParseError::Truncated {
                    expected: start + 1,
                    actual: len,
                });
            }
        }
    }
    match allowed_range.end_bound() {
        std::ops::Bound::Unbounded => (),
        std::ops::Bound::Included(end) => {
            if len > *end {
                return Err(StunParseError::TooLarge {
                    expected: *end,
                    actual: len,
                });
            }
        }
        std::ops::Bound::Excluded(end) => {
            if len >= *end {
                return Err(StunParseError::TooLarge {
                    expected: *end - 1,
                    actual: len,
                });
            }
        }
    }
    Ok(())
}

impl<'a> From<RawAttribute<'a>> for Vec<u8> {
    fn from(f: RawAttribute) -> Self {
        f.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_type() {
        let _log = crate::tests::test_init_log();
        let atype = ErrorCode::TYPE;
        let anum: u16 = atype.into();
        assert_eq!(atype, anum.into());
    }

    #[test]
    fn short_attribute_header() {
        let _log = crate::tests::test_init_log();
        let data = [0; 1];
        // not enough data to parse the header
        let res: Result<AttributeHeader, _> = data.as_ref().try_into();
        assert!(res.is_err());
    }

    #[test]
    fn raw_attribute_construct() {
        let _log = crate::tests::test_init_log();
        let a = RawAttribute::new(1.into(), &[80, 160]);
        assert_eq!(a.get_type(), 1.into());
        let bytes: Vec<_> = a.into();
        assert_eq!(bytes, &[0, 1, 0, 2, 80, 160, 0, 0]);
        let b = RawAttribute::from_bytes(bytes.as_ref()).unwrap();
        assert_eq!(b.get_type(), 1.into());
    }

    #[test]
    fn raw_attribute_encoding() {
        let _log = crate::tests::test_init_log();
        let orig = RawAttribute::new(1.into(), &[80, 160]);
        assert_eq!(orig.get_type(), 1.into());
        let mut data: Vec<_> = orig.into();
        let len = data.len();
        // one byte too big vs data size
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 + 1);
        assert!(matches!(
            RawAttribute::from_bytes(data.as_ref()),
            Err(StunParseError::Truncated {
                expected: 5,
                actual: 4
            })
        ));
    }

    #[test]
    fn test_check_len() {
        let _log = crate::tests::test_init_log();
        assert!(check_len(4, ..).is_ok());
        assert!(check_len(4, 0..).is_ok());
        assert!(check_len(4, 0..8).is_ok());
        assert!(check_len(4, 0..=8).is_ok());
        assert!(check_len(4, ..=8).is_ok());
        assert!(matches!(
            check_len(4, ..4),
            Err(StunParseError::TooLarge {
                expected: 3,
                actual: 4
            })
        ));
        assert!(matches!(
            check_len(4, 5..),
            Err(StunParseError::Truncated {
                expected: 5,
                actual: 4
            })
        ));
        assert!(matches!(
            check_len(4, ..=3),
            Err(StunParseError::TooLarge {
                expected: 3,
                actual: 4
            })
        ));
        assert!(matches!(
            check_len(
                4,
                (std::ops::Bound::Excluded(4), std::ops::Bound::Unbounded)
            ),
            Err(StunParseError::Truncated {
                expected: 5,
                actual: 4
            })
        ));
    }
}
