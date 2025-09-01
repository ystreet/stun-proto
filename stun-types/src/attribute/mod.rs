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
//! There are two levels of attribute implementations:
//! 1. A generic [`RawAttribute`] which contains the [`AttributeHeader`] (type and length) and the
//!    byte sequence of data (either borrowed or owned). Parsing a
//!    [`Message`](crate::message::Message) will only perform zerocopy parsing to this level. Any
//!    attribute-specific restrictions on the actual contents of the data should be performed by
//!    concrete attribute implementations.
//! 2. Concrete implementations based on implementing [`Attribute`], and [`AttributeStaticType`].
//!    These concrete attribute implementations have much more ergonomic API specific to their
//!    particular needs. A concrete attribute implementation may have restrictions on what data is
//!    allowed to be parsed from a [`RawAttribute`] that should return errors when calling
//!    [`AttributeFromRaw::from_raw_ref`].
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
//! let software = Software::from_raw(raw).unwrap();
//! assert_eq!(software.software(), software_name);
//! ```
//!
//! ### Defining your own [`Attribute`]
//!
//! ```
//! # use stun_types::prelude::*;
//! use byteorder::{BigEndian, ByteOrder};
//! use stun_types::attribute::{AttributeType, RawAttribute};
//! use stun_types::message::StunParseError;
//! #[derive(Debug)]
//! struct MyAttribute {
//!    value: u32,
//! }
//! impl AttributeStaticType for MyAttribute {
//!    const TYPE: AttributeType = AttributeType::new(0x8851);
//! }
//! impl Attribute for MyAttribute {
//!    fn get_type(&self) -> AttributeType {
//!        Self::TYPE
//!    }
//!
//!    fn length(&self) -> u16 {
//!        4
//!    }
//! }
//! impl AttributeWrite for MyAttribute {
//!     fn to_raw(&self) -> RawAttribute<'_> {
//!         let mut ret = [0; 4];
//!         BigEndian::write_u32(&mut ret, self.value);
//!         RawAttribute::new(MyAttribute::TYPE, &ret).into_owned()
//!     }
//!     fn write_into_unchecked(&self, dest: &mut [u8]) {
//!         self.write_header_unchecked(dest);
//!         BigEndian::write_u32(&mut dest[4..], self.value);
//!     }
//! }
//! impl AttributeFromRaw<'_> for MyAttribute {
//!     fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
//!     where
//!         Self: Sized,
//!     {
//!         raw.check_type_and_len(Self::TYPE, 4..=4)?;
//!         let value = BigEndian::read_u32(&raw.value);
//!         Ok(Self {
//!             value,
//!         })
//!     }
//! }
//!
//! // Optional: if you want this attribute to be displayed nicely when the corresponding
//! // `RawAttribute` (based on `AttributeType`) is formatted using `RawAttribute`'s `Display`
//! // implementation.
//! impl core::fmt::Display for MyAttribute {
//!     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//!         write!(f, "MyAttribute: {}", self.value)
//!     }
//! }
//! # #[cfg(feature = "std")]
//! stun_types::attribute_display!(MyAttribute);
//! # #[cfg(feature = "std")]
//! MyAttribute::TYPE.add_name("MY-ATTRIBUTE");
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
//! let my_attr = MyAttribute::from_raw(raw).unwrap();
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
use alloc::boxed::Box;
use alloc::vec::Vec;

use byteorder::{BigEndian, ByteOrder};

#[cfg(feature = "std")]
use alloc::collections::BTreeMap;
#[cfg(feature = "std")]
use std::sync::{Mutex, OnceLock};

/// A closure definition for an externally provided `Display` implementation for a [`RawAttribute`].
///
/// Typically, a concrete [`Attribute`] implements `Display` and
/// [`attribute_display`](crate::attribute_display) can be used
/// to generate and install this closure.
///
/// See the module level documentation for an example.
pub type AttributeDisplay =
    fn(&RawAttribute<'_>, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result;
#[cfg(feature = "std")]
static ATTRIBUTE_EXTERNAL_DISPLAY_IMPL: OnceLock<Mutex<BTreeMap<AttributeType, AttributeDisplay>>> =
    OnceLock::new();

/// Adds an externally provided Display implementation for a particular [`AttributeType`].  Any
/// previous implementation is overidden.
#[cfg(feature = "std")]
pub fn add_display_impl(atype: AttributeType, imp: AttributeDisplay) {
    let mut display_impls = ATTRIBUTE_EXTERNAL_DISPLAY_IMPL
        .get_or_init(Default::default)
        .lock()
        .unwrap();
    display_impls.insert(atype, imp);
}

/// Implement an [`AttributeDisplay`] closure for an [`Attribute`] from a [`RawAttribute`] and calls
/// [`add_display_impl`] with the generated closure.
///
/// # Examples
/// ```
/// use stun_types::attribute::{AttributeType, Attribute, AttributeStaticType, AttributeFromRaw};
/// use stun_types::attribute::RawAttribute;
/// use stun_types::message::StunParseError;
/// #[derive(Debug)]
/// struct MyAttribute {}
/// impl AttributeStaticType for MyAttribute {
///    const TYPE: AttributeType = AttributeType::new(0x8852);
/// }
/// impl Attribute for MyAttribute {
///    fn get_type(&self) -> AttributeType {
///        Self::TYPE
///    }
///    fn length(&self) -> u16 {
///        0
///    }
/// }
/// impl AttributeFromRaw<'_> for MyAttribute {
///     fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
///     where
///         Self: Sized,
///     {
///         raw.check_type_and_len(Self::TYPE, 0..=0)?;
///         Ok(Self {})
///    }
/// }
/// // An Attribute would also implement AttributeWrite but that has been omitted for brevity.
/// impl core::fmt::Display for MyAttribute {
///     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
///         write!(f, "MyAttribute")
///     }
/// }
/// # #[cfg(feature = "std")]
/// # {
/// stun_types::attribute_display!(MyAttribute);
/// let attr = RawAttribute::new(MyAttribute::TYPE, &[]);
/// let display_str = format!("{attr}");
/// assert_eq!(display_str, "MyAttribute");
/// # }
/// ```
#[macro_export]
macro_rules! attribute_display {
    ($typ:ty) => {{
        let imp = |attr: &$crate::attribute::RawAttribute<'_>,
                   f: &mut core::fmt::Formatter<'_>|
         -> core::fmt::Result {
            if let Ok(attr) = <$typ>::from_raw_ref(attr) {
                write!(f, "{}", attr)
            } else {
                write!(
                    f,
                    "{}(Malformed): len: {}, data: {:?})",
                    attr.get_type(),
                    attr.header.length(),
                    attr.value
                )
            }
        };

        $crate::attribute::add_display_impl(<$typ>::TYPE, imp);
    }};
}

#[cfg(feature = "std")]
static ATTRIBUTE_TYPE_NAME_MAP: OnceLock<Mutex<BTreeMap<AttributeType, &'static str>>> =
    OnceLock::new();

/// The type of an [`Attribute`] in a STUN [`Message`](crate::message::Message)
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttributeType(u16);

impl core::fmt::Display for AttributeType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}({:#x}: {})", self.0, self.0, self.name())
    }
}

impl AttributeType {
    /// Add the name for a particular [`AttributeType`] for formatting purposes.
    #[cfg(feature = "std")]
    pub fn add_name(self, name: &'static str) {
        let mut anames = ATTRIBUTE_TYPE_NAME_MAP
            .get_or_init(Default::default)
            .lock()
            .unwrap();
        anames.insert(self, name);
    }

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
            _ => {
                #[cfg(feature = "std")]
                {
                    let anames = ATTRIBUTE_TYPE_NAME_MAP
                        .get_or_init(Default::default)
                        .lock()
                        .unwrap();
                    if let Some(name) = anames.get(&self) {
                        return name;
                    }
                }
                "unknown"
            }
        }
    }

    /// Check if comprehension is required for an `AttributeType`.  All attribute
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

    fn to_bytes(self) -> [u8; 4] {
        let mut ret = [0; 4];
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
impl From<AttributeHeader> for [u8; 4] {
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

/// A static type for an [`Attribute`]
pub trait AttributeStaticType {
    /// The [`AttributeType`]
    const TYPE: AttributeType;
}

/// A STUN attribute for use in [`Message`](crate::message::Message)s
pub trait Attribute: core::fmt::Debug + core::marker::Sync + core::marker::Send {
    /// Retrieve the type of an `Attribute`.
    fn get_type(&self) -> AttributeType;

    /// Retrieve the length of an `Attribute`.  This is not the padded length as stored in a
    /// `Message` and does not include the size of the attribute header.
    fn length(&self) -> u16;
}

/// A trait for converting from a [`RawAttribute`] to a concrete [`Attribute`].
pub trait AttributeFromRaw<'a>: Attribute {
    /// Produce an `Attribute` from a `RawAttribute`
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized;

    /// Produce an `Attribute` from a `RawAttribute`
    fn from_raw(raw: RawAttribute<'a>) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::from_raw_ref(&raw)
    }
}

fn padded_attr_len(len: usize) -> usize {
    if len % 4 == 0 {
        len
    } else {
        len + 4 - len % 4
    }
}

/// Automatically implemented trait providing some helper functions for [`Attribute`]s.
pub trait AttributeExt {
    /// The length in bytes of an [`Attribute`] as stored in a [`Message`](crate::message::Message)
    /// including any padding and the attribute header.
    fn padded_len(&self) -> usize;
}

impl<A: Attribute + ?Sized> AttributeExt for A {
    fn padded_len(&self) -> usize {
        4 + padded_attr_len(self.length() as usize)
    }
}

/// Trait required when implementing writing an [`Attribute`] to a sequence of bytes
pub trait AttributeWrite: Attribute {
    /// Write attribute to the provided destination buffer.
    ///
    /// Panics if the destination buffer is not large enough
    fn write_into_unchecked(&self, dest: &mut [u8]);
    /// Produce a [`RawAttribute`] from this [`Attribute`]
    fn to_raw(&self) -> RawAttribute<'_>;
}

/// Automatically implemented trait providing helper functionality for writing an [`Attribute`] to
/// a sequence of bytes.
pub trait AttributeWriteExt: AttributeWrite {
    /// Write the 4 byte attribute header into the provided destination buffer returning the
    /// number of bytes written.
    ///
    /// Panics if the destination cannot hold at least 4 bytes of data.
    fn write_header_unchecked(&self, dest: &mut [u8]) -> usize;
    /// Write the 4 byte attribute header into the provided destination buffer returning the
    /// number of bytes written, or an error.
    fn write_header(&self, dest: &mut [u8]) -> Result<usize, StunWriteError>;
    /// Write this attribute into the provided destination buffer returning the number of bytes
    /// written, or an error.
    fn write_into(&self, dest: &mut [u8]) -> Result<usize, StunWriteError>;
}

impl<A: AttributeWrite + ?Sized> AttributeWriteExt for A {
    fn write_header(&self, dest: &mut [u8]) -> Result<usize, StunWriteError> {
        if dest.len() < 4 {
            return Err(StunWriteError::TooSmall {
                expected: 4,
                actual: dest.len(),
            });
        }
        self.write_header_unchecked(dest);
        Ok(4)
    }
    fn write_header_unchecked(&self, dest: &mut [u8]) -> usize {
        AttributeHeader {
            atype: self.get_type(),
            length: self.length(),
        }
        .write_into(dest);
        4
    }

    fn write_into(&self, dest: &mut [u8]) -> Result<usize, StunWriteError> {
        let len = self.padded_len();
        if len > dest.len() {
            return Err(StunWriteError::TooSmall {
                expected: len,
                actual: dest.len(),
            });
        }
        self.write_into_unchecked(dest);
        Ok(len)
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
    ($this:ident, $f:ident, $CamelType:ty) => {{
        if let Ok(attr) = <$CamelType>::from_raw_ref($this) {
            write!($f, "{}", attr)
        } else {
            write!(
                $f,
                "{}(Malformed): len: {}, data: {:?})",
                $this.get_type(),
                $this.header.length(),
                $this.value
            )
        }
    }};
}

impl core::fmt::Display for RawAttribute<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // try to get a more specialised display
        match self.get_type() {
            Username::TYPE => display_attr!(self, f, Username),
            MessageIntegrity::TYPE => display_attr!(self, f, MessageIntegrity),
            ErrorCode::TYPE => display_attr!(self, f, ErrorCode),
            UnknownAttributes::TYPE => display_attr!(self, f, UnknownAttributes),
            Realm::TYPE => display_attr!(self, f, Realm),
            Nonce::TYPE => display_attr!(self, f, Nonce),
            MessageIntegritySha256::TYPE => {
                display_attr!(self, f, MessageIntegritySha256)
            }
            PasswordAlgorithm::TYPE => display_attr!(self, f, PasswordAlgorithm),
            //UserHash::TYPE => display_attr!(self, UserHash),
            XorMappedAddress::TYPE => display_attr!(self, f, XorMappedAddress),
            PasswordAlgorithms::TYPE => display_attr!(self, f, PasswordAlgorithms),
            AlternateDomain::TYPE => display_attr!(self, f, AlternateDomain),
            Software::TYPE => display_attr!(self, f, Software),
            AlternateServer::TYPE => display_attr!(self, f, AlternateServer),
            Fingerprint::TYPE => display_attr!(self, f, Fingerprint),
            _ => {
                #[cfg(feature = "std")]
                {
                    let mut display_impls = ATTRIBUTE_EXTERNAL_DISPLAY_IMPL
                        .get_or_init(|| Default::default())
                        .lock()
                        .unwrap();
                    if let Some(imp) = display_impls.get_mut(&self.get_type()) {
                        return imp(self, f);
                    }
                }
                write!(
                    f,
                    "RawAttribute (type: {:?}, len: {}, data: {:?})",
                    self.header.get_type(),
                    self.header.length(),
                    &self.value
                )
            }
        }
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

    /// Create a new owned [`RawAttribute`]
    pub fn new_owned(atype: AttributeType, data: Box<[u8]>) -> Self {
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

    /// Helper for checking that a raw attribute is of a particular type and has a data length
    /// within a certain range.
    pub fn check_type_and_len(
        &self,
        atype: AttributeType,
        allowed_range: impl core::ops::RangeBounds<usize>,
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

impl Attribute for RawAttribute<'_> {
    /// Returns the [`AttributeType`] of this [`RawAttribute`]
    fn get_type(&self) -> AttributeType {
        self.header.get_type()
    }

    /// Returns the length of this [`RawAttribute`]
    fn length(&self) -> u16 {
        self.value.len() as u16
    }
}

impl AttributeWrite for RawAttribute<'_> {
    /// Write this [`RawAttribute`] into a byte slice.  Returns the number of bytes written.
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        let len = self.padded_len();
        self.header.write_into(dest);
        let mut offset = 4;
        dest[offset..offset + self.value.len()].copy_from_slice(&self.value);
        offset += self.value.len();
        if len - offset > 0 {
            dest[offset..len].fill(0);
        }
    }

    fn to_raw(&self) -> RawAttribute<'_> {
        self.clone()
    }
}

impl<'a, A: AttributeWrite> From<&'a A> for RawAttribute<'a> {
    fn from(value: &'a A) -> Self {
        value.to_raw()
    }
}

fn check_len(
    len: usize,
    allowed_range: impl core::ops::RangeBounds<usize>,
) -> Result<(), StunParseError> {
    match allowed_range.start_bound() {
        core::ops::Bound::Unbounded => (),
        core::ops::Bound::Included(start) => {
            if len < *start {
                return Err(StunParseError::Truncated {
                    expected: *start,
                    actual: len,
                });
            }
        }
        core::ops::Bound::Excluded(start) => {
            if len <= *start {
                return Err(StunParseError::Truncated {
                    expected: start + 1,
                    actual: len,
                });
            }
        }
    }
    match allowed_range.end_bound() {
        core::ops::Bound::Unbounded => (),
        core::ops::Bound::Included(end) => {
            if len > *end {
                return Err(StunParseError::TooLarge {
                    expected: *end,
                    actual: len,
                });
            }
        }
        core::ops::Bound::Excluded(end) => {
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

impl From<RawAttribute<'_>> for Vec<u8> {
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
                (core::ops::Bound::Excluded(4), core::ops::Bound::Unbounded)
            ),
            Err(StunParseError::Truncated {
                expected: 5,
                actual: 4
            })
        ));
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_external_display_impl() {
        let _log = crate::tests::test_init_log();
        let atype = AttributeType::new(0xFFFF);
        let imp = |attr: &RawAttribute<'_>,
                   f: &mut core::fmt::Formatter<'_>|
         -> core::fmt::Result { write!(f, "Custom {}", attr.value[0]) };
        add_display_impl(atype, imp);
        let data = [4, 0];
        let attr = RawAttribute::new(atype, &data);
        let display_str = alloc::format!("{}", attr);
        assert_eq!(display_str, "Custom 4");

        atype.add_name("SOME-NAME");
        assert_eq!(atype.name(), "SOME-NAME");

        attribute_display!(Fingerprint);
    }
}
