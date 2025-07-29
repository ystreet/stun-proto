// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN Messages
//!
//! Provides types for generating, parsing, and manipulating STUN messages as specified in one of
//! [RFC8489], [RFC5389], or [RFC3489].
//!
//! Message parsing is zerocopy by default through the [`RawAttribute`] struct. Converting to a
//! concrete attribute implementation (e.g. [`Software`]) may incur a
//! copy depending on the attribute implementation.
//!
//! The destination for a written Message is completely customizable through the [`MessageWrite`]
//! trait. It is therefore possible to write directly into network provided buffers for increased
//! performance and throughput.
//!
//! [RFC8489]: https://tools.ietf.org/html/rfc8489
//! [RFC5389]: https://tools.ietf.org/html/rfc5389
//! [RFC3489]: https://tools.ietf.org/html/rfc3489
//!
//! ## Examples
//!
//! ### Parse a STUN [`Message`]
//!
//! ```
//! use stun_types::prelude::*;
//! use stun_types::attribute::{RawAttribute, PasswordAlgorithm, PasswordAlgorithmValue};
//! use stun_types::message::{Message, MessageType, MessageClass, BINDING};
//!
//! let msg_data = [
//!     0x00, 0x01, 0x00, 0x08, // method, class and length
//!     0x21, 0x12, 0xA4, 0x42, // Fixed STUN magic bytes
//!     0x00, 0x00, 0x00, 0x00, // \
//!     0x00, 0x00, 0x00, 0x00, // } transaction ID
//!     0x00, 0x00, 0x73, 0x92, // /
//!     0x00, 0x1D, 0x00, 0x04, // PasswordAlgorithm attribute header (type and length)
//!     0x00, 0x02, 0x00, 0x00  // PasswordAlgorithm attribute value
//! ];
//! let msg = Message::from_bytes(&msg_data).unwrap();
//!
//! // the various parts of a message can be retreived
//! assert_eq!(msg.get_type(), MessageType::from_class_method(MessageClass::Request, BINDING));
//! assert_eq!(msg.transaction_id(), 0x7392.into());
//!
//! // Attributes can be retrieved as raw values.
//! let msg_attr = msg.raw_attribute(0x1D.into()).unwrap();
//! let attr = RawAttribute::new(0x1D.into(), &[0, 2, 0, 0]);
//! assert_eq!(msg_attr, attr);
//!
//! // Or as typed values
//! let attr = msg.attribute::<PasswordAlgorithm>().unwrap();
//! assert_eq!(attr.algorithm(), PasswordAlgorithmValue::SHA256);
//! ```
//!
//! ### Generating a [`Message`]
//!
//! ```
//! use stun_types::prelude::*;
//! use stun_types::attribute::Software;
//! use stun_types::message::{Message, MessageWriteVec, BINDING};
//!
//! // Automatically generates a transaction ID.
//! let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
//!
//! let software_name = "stun-types";
//! let software = Software::new(software_name).unwrap();
//! assert_eq!(software.software(), software_name);
//! msg.add_attribute(&software).unwrap();
//!
//! let attribute_data = [
//!     0x80, 0x22, 0x00, 0x0a, // attribute type (0x8022) and length (0x000a)
//!     0x73, 0x74, 0x75, 0x6E, // s t u n
//!     0x2D, 0x74, 0x79, 0x70, // - t y p
//!     0x65, 0x73, 0x00, 0x00  // e s
//! ];
//!
//! let msg_data = msg.finish();
//! // ignores the randomly generated transaction id
//! assert_eq!(msg_data[20..], attribute_data);
//! ```

use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::{Mutex, OnceLock};

use byteorder::{BigEndian, ByteOrder};

use crate::attribute::*;

use tracing::{trace, warn};

/// The value of the magic cookie (in network byte order) as specified in RFC5389, and RFC8489.
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// The method in a STUN [`Message`]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Method(u16);

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({:#x}: {})", self.0, self.0, self.name())
    }
}

static METHOD_NAME_MAP: OnceLock<Mutex<HashMap<Method, &'static str>>> = OnceLock::new();

impl Method {
    /// Add the name for a particular [`Method`] for formatting purposes.
    pub fn add_name(self, name: &'static str) {
        let mut mnames = METHOD_NAME_MAP
            .get_or_init(Default::default)
            .lock()
            .unwrap();
        mnames.insert(self, name);
    }

    /// Create a new [`Method`] from an existing value
    ///
    /// Note: the value passed in is not encoded as in a stun message
    ///
    /// Panics if the value is out of range (>= 0xf000)
    ///
    /// # Examples
    /// ```
    /// # use stun_types::message::Method;
    /// assert_eq!(Method::new(0x123).value(), 0x123);
    /// ```
    pub const fn new(val: u16) -> Self {
        if val >= 0xf000 {
            panic!("Method value is out of range!");
        }
        Self(val)
    }

    /// Return the integer value of this [`Method`]
    ///
    /// Note: the value returned is not encoded as in a stun message
    ///
    /// # Examples
    /// ```
    /// # use stun_types::message::Method;
    /// assert_eq!(Method::new(0x123).value(), 0x123);
    /// ```
    pub fn value(&self) -> u16 {
        self.0
    }

    /// Returns a human readable name of this `Method` or "unknown"
    ///
    /// # Examples
    /// ```
    /// # use stun_types::attribute::*;
    /// assert_eq!(XorMappedAddress::TYPE.name(), "XOR-MAPPED-ADDRESS");
    /// ```
    pub fn name(self) -> &'static str {
        match self {
            BINDING => "BINDING",
            _ => {
                let mnames = METHOD_NAME_MAP
                    .get_or_init(Default::default)
                    .lock()
                    .unwrap();
                if let Some(name) = mnames.get(&self) {
                    name
                } else {
                    "unknown"
                }
            }
        }
    }
}

/// The value of the binding message type.  Can be used in either a request or an indication
/// message.
pub const BINDING: Method = Method::new(0x0001);

/// Possible errors when parsing a STUN message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StunParseError {
    /// Not a STUN message.
    #[error("The provided data is not a STUN message")]
    NotStun,
    /// The message has been truncated
    #[error("Not enough data available to parse the packet, expected {}, actual {}", .expected, .actual)]
    Truncated {
        /// The expeced number of bytes
        expected: usize,
        /// The encountered number of bytes
        actual: usize,
    },
    /// The message has been truncated
    #[error("Too many bytes for this data, expected {}, actual {}", .expected, .actual)]
    TooLarge {
        /// The expeced number of bytes
        expected: usize,
        /// The encountered number of bytes
        actual: usize,
    },
    /// Integrity value does not match computed value
    #[error("Integrity value does not match")]
    IntegrityCheckFailed,
    /// An attribute was not found in the message
    #[error("Missing attribute {}", .0)]
    MissingAttribute(AttributeType),
    /// An attribute was found after the message integrity attribute
    #[error("An attribute {} was encountered after a message integrity attribute", .0)]
    AttributeAfterIntegrity(AttributeType),
    /// An attribute was found after the message integrity attribute
    #[error("An attribute {} was encountered after a fingerprint attribute", .0)]
    AttributeAfterFingerprint(AttributeType),
    /// Fingerprint does not match the data.
    #[error("Fingerprint does not match")]
    FingerprintMismatch,
    /// The provided data does not match the message
    #[error("The provided data does not match the message")]
    DataMismatch,
    /// The attribute contains invalid data
    #[error("The attribute contains invalid data")]
    InvalidAttributeData,
    /// The attribute does not parse this data
    #[error("Cannot parse with this attribute")]
    WrongAttributeImplementation,
}

/// Errors produced when writing a STUN message
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StunWriteError {
    /// The message already has this attribute
    #[error("The attribute already exists in the message")]
    AttributeExists(AttributeType),
    /// The fingerprint attribute already exists. Cannot write any further attributes
    #[error("The message already contains a fingerprint attribute")]
    FingerprintExists,
    /// A message integrity attribute already exists. Cannot write any further attributes
    #[error("The message already contains a message intregrity attribute")]
    MessageIntegrityExists,
    /// The message has been truncated
    #[error("Too many bytes for this data, expected {}, actual {}", .expected, .actual)]
    TooLarge {
        /// The expeced number of bytes
        expected: usize,
        /// The encountered number of bytes
        actual: usize,
    },
    /// The message has been truncated
    #[error("Not enough data available to parse the packet, expected {}, actual {}", .expected, .actual)]
    TooSmall {
        /// The expected number of bytes
        expected: usize,
        /// The encountered number of bytes
        actual: usize,
    },
    /// Failed to compute integrity
    #[error("Failed to compute integrity")]
    IntegrityFailed,
    /// Out of range input provided
    #[error("Out of range input provided")]
    OutOfRange {
        /// The value provided.
        value: usize,
        /// The minimum allowed value.
        min: usize,
        /// The maximum allowed value.
        max: usize,
    },
}

/// Structure for holding the required credentials for handling long-term STUN credentials
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LongTermCredentials {
    username: String,
    password: String,
    realm: String,
}

impl LongTermCredentials {
    /// Create a new set of [`LongTermCredentials`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::LongTermCredentials;
    /// let credentials = LongTermCredentials::new(
    ///     "user".to_string(),
    ///     "pass".to_string(),
    ///     "realm".to_string(),
    /// );
    /// assert_eq!(credentials.username(), "user");
    /// assert_eq!(credentials.password(), "pass");
    /// assert_eq!(credentials.realm(), "realm");
    /// ```
    pub fn new(username: String, password: String, realm: String) -> Self {
        Self {
            username,
            password,
            realm,
        }
    }

    /// The configured username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The configured password
    pub fn password(&self) -> &str {
        &self.password
    }

    /// The configured realm
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

/// Structure for holding the required credentials for handling short-term STUN credentials
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ShortTermCredentials {
    password: String,
}

impl ShortTermCredentials {
    /// Create a new set of [`ShortTermCredentials`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::ShortTermCredentials;
    /// let credentials = ShortTermCredentials::new("password".to_string());
    /// assert_eq!(credentials.password(), "password");
    /// ```
    pub fn new(password: String) -> Self {
        Self { password }
    }

    /// The configured password
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// Enum for holding the credentials used to sign or verify a [`Message`]
///
/// This can either be a set of [`ShortTermCredentials`] or [`LongTermCredentials`]`
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum MessageIntegrityCredentials {
    /// Short term integrity credentials.
    ShortTerm(ShortTermCredentials),
    /// Long term integrity credentials.
    LongTerm(LongTermCredentials),
}

impl From<LongTermCredentials> for MessageIntegrityCredentials {
    fn from(value: LongTermCredentials) -> Self {
        MessageIntegrityCredentials::LongTerm(value)
    }
}

impl From<ShortTermCredentials> for MessageIntegrityCredentials {
    fn from(value: ShortTermCredentials) -> Self {
        MessageIntegrityCredentials::ShortTerm(value)
    }
}

impl MessageIntegrityCredentials {
    fn make_hmac_key(&self) -> Vec<u8> {
        match self {
            MessageIntegrityCredentials::ShortTerm(short) => short.password.clone().into(),
            MessageIntegrityCredentials::LongTerm(long) => {
                use md5::{Digest, Md5};
                let data = long.username.clone()
                    + ":"
                    + &long.realm.clone()
                    + ":"
                    + &long.password.clone();
                let mut digest = Md5::new();
                digest.update(&data);
                digest.finalize().to_vec()
            }
        }
    }
}

/// The class of a [`Message`].
///
/// There are four classes of [`Message`]s within the STUN protocol:
///
///  - [Request][`MessageClass::Request`] indicates that a request is being made and a
///    response is expected.
///  - An [Indication][`MessageClass::Indication`] is a fire and forget [`Message`] where
///    no response is required or expected.
///  - [Success][`MessageClass::Success`] indicates that a [Request][`MessageClass::Request`]
///    was successfully handled and the
///  - [Error][`MessageClass::Error`] class indicates that an error was produced.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MessageClass {
    /// A request that is expecting a response of either Success, or Error.
    Request,
    /// A request that does not expect a response.
    Indication,
    /// A success response to a previous Request.
    Success,
    /// An error response to a previous Request.
    Error,
}

impl MessageClass {
    /// Returns whether this [`MessageClass`] is of a response type.  i.e. is either
    /// [`MessageClass::Success`] or [`MessageClass::Error`].
    pub fn is_response(self) -> bool {
        matches!(self, MessageClass::Success | MessageClass::Error)
    }

    fn to_bits(self) -> u16 {
        match self {
            MessageClass::Request => 0x000,
            MessageClass::Indication => 0x010,
            MessageClass::Success => 0x100,
            MessageClass::Error => 0x110,
        }
    }
}

/// The type of a [`Message`].  A combination of a [`MessageClass`] and a STUN method.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MessageType(u16);

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MessageType(class: {:?}, method: {}",
            self.class(),
            self.method(),
        )
    }
}

impl MessageType {
    /// Create a new [`MessageType`] from the provided [`MessageClass`] and method
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// assert_eq!(mtype.has_class(MessageClass::Indication), true);
    /// assert_eq!(mtype.has_method(BINDING), true);
    /// ```
    pub fn from_class_method(class: MessageClass, method: Method) -> Self {
        let class_bits = MessageClass::to_bits(class);
        let method = method.value();
        let method_bits = method & 0xf | (method & 0x70) << 1 | (method & 0xf80) << 2;
        // trace!("MessageType from class {:?} and method {:?} into {:?}", class, method,
        //     class_bits | method_bits);
        Self(class_bits | method_bits)
    }

    /// Retrieves the class of a [`MessageType`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// assert_eq!(mtype.class(), MessageClass::Indication);
    /// ```
    pub fn class(self) -> MessageClass {
        let class = (self.0 & 0x10) >> 4 | (self.0 & 0x100) >> 7;
        match class {
            0x0 => MessageClass::Request,
            0x1 => MessageClass::Indication,
            0x2 => MessageClass::Success,
            0x3 => MessageClass::Error,
            _ => unreachable!(),
        }
    }

    /// Returns whether class of a [`MessageType`] is equal to the provided [`MessageClass`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// assert!(mtype.has_class(MessageClass::Indication));
    /// ```
    pub fn has_class(self, cls: MessageClass) -> bool {
        self.class() == cls
    }

    /// Returns whether the class of a [`MessageType`] indicates a response [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{MessageType, MessageClass, BINDING};
    /// assert_eq!(MessageType::from_class_method(MessageClass::Indication, BINDING)
    ///     .is_response(), false);
    /// assert_eq!(MessageType::from_class_method(MessageClass::Request, BINDING)
    ///     .is_response(), false);
    /// assert_eq!(MessageType::from_class_method(MessageClass::Success, BINDING)
    ///     .is_response(), true);
    /// assert_eq!(MessageType::from_class_method(MessageClass::Error, BINDING)
    ///     .is_response(), true);
    /// ```
    pub fn is_response(self) -> bool {
        self.class().is_response()
    }

    /// Returns the method of a [`MessageType`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// assert_eq!(mtype.method(), BINDING);
    /// ```
    pub fn method(self) -> Method {
        Method::new(self.0 & 0xf | (self.0 & 0xe0) >> 1 | (self.0 & 0x3e00) >> 2)
    }

    /// Returns whether the method of a [`MessageType`] is equal to the provided value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// assert_eq!(mtype.has_method(BINDING), true);
    /// ```
    pub fn has_method(self, method: Method) -> bool {
        self.method() == method
    }

    /// Convert a [`MessageType`] to network bytes
    pub fn write_into(&self, dest: &mut [u8]) {
        BigEndian::write_u16(dest, self.0);
    }

    /// Convert a [`MessageType`] to network bytes
    pub fn to_bytes(self) -> Vec<u8> {
        let mut ret = vec![0; 2];
        BigEndian::write_u16(&mut ret[0..2], self.0);
        ret
    }

    /// Convert a set of network bytes into a [`MessageType`] or return an error
    pub fn from_bytes(data: &[u8]) -> Result<Self, StunParseError> {
        let data = BigEndian::read_u16(data);
        if data & 0xc000 != 0x0 {
            /* not a stun packet */
            return Err(StunParseError::NotStun);
        }
        Ok(Self(data))
    }
}
impl TryFrom<&[u8]> for MessageType {
    type Error = StunParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        MessageType::from_bytes(value)
    }
}

/// A unique transaction identifier for each message and it's (possible) response.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct TransactionId {
    id: u128,
}

impl TransactionId {
    /// Generate a new STUN transaction identifier.
    pub fn generate() -> TransactionId {
        use rand::Rng;
        let mut rng = rand::rng();
        rng.random::<u128>().into()
    }
}

impl From<u128> for TransactionId {
    fn from(id: u128) -> Self {
        Self {
            id: id & 0xffff_ffff_ffff_ffff_ffff_ffff,
        }
    }
}
impl From<TransactionId> for u128 {
    fn from(id: TransactionId) -> Self {
        id.id
    }
}
impl std::fmt::Display for TransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.id)
    }
}

/// The fixed length header of a STUN message.  Allows reading the message header for a quick
/// check if this message is a valid STUN message.  Can also be used to expose the length of the
/// complete message without needing to receive the entire message.
#[derive(Debug)]
pub struct MessageHeader {
    mtype: MessageType,
    transaction_id: TransactionId,
    length: u16,
}

impl MessageHeader {
    /// The length of the STUN message header.
    pub const LENGTH: usize = 20;

    /// Deserialize a `MessageHeader`
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{MessageHeader, MessageType, MessageClass, BINDING};
    /// let msg_data = [0, 1, 0, 8, 33, 18, 164, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232];
    /// let message = MessageHeader::from_bytes(&msg_data).unwrap();
    /// assert_eq!(message.get_type(), MessageType::from_class_method(MessageClass::Request, BINDING));
    /// assert_eq!(message.transaction_id(), 1000.into());
    /// assert_eq!(message.data_length(), 8);
    /// ```
    pub fn from_bytes(data: &[u8]) -> Result<Self, StunParseError> {
        if data.len() < 20 {
            return Err(StunParseError::Truncated {
                expected: 20,
                actual: data.len(),
            });
        }
        let mtype = MessageType::from_bytes(data)?;
        let mlength = BigEndian::read_u16(&data[2..]);
        let tid = BigEndian::read_u128(&data[4..]);
        let cookie = (tid >> 96) as u32;
        if cookie != MAGIC_COOKIE {
            warn!(
                "malformed cookie constant {:?} != stored data {:?}",
                MAGIC_COOKIE, cookie
            );
            return Err(StunParseError::NotStun);
        }

        Ok(Self {
            mtype,
            transaction_id: tid.into(),
            length: mlength,
        })
    }

    /// The number of bytes of content in this [`MessageHeader`]. Adding both `data_length()`
    /// and [`MessageHeader::LENGTH`] will result in the size of the complete STUN message.
    pub fn data_length(&self) -> u16 {
        self.length
    }

    /// The [`TransactionId`] of this [`MessageHeader`]
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// The [`MessageType`] of this [`MessageHeader`]
    pub fn get_type(&self) -> MessageType {
        self.mtype
    }

    fn new(mtype: MessageType, transaction_id: TransactionId, length: u16) -> Self {
        Self {
            mtype,
            transaction_id,
            length,
        }
    }

    fn write_into(&self, dest: &mut [u8]) {
        self.mtype.write_into(&mut dest[..2]);
        let transaction: u128 = self.transaction_id.into();
        let tid = (MAGIC_COOKIE as u128) << 96 | transaction & 0xffff_ffff_ffff_ffff_ffff_ffff;
        BigEndian::write_u128(&mut dest[4..20], tid);
        BigEndian::write_u16(&mut dest[2..4], self.length);
    }
}

/// The structure that encapsulates the entirety of a STUN message
///
/// Contains the [`MessageType`], a transaction ID, and a list of STUN
/// [`Attribute`]
#[derive(Debug, Clone)]
pub struct Message<'a> {
    data: &'a [u8],
}

impl std::fmt::Display for Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Message(class: {:?}, method: {}, transaction: {}, attributes: ",
            self.get_type().class(),
            self.get_type().method(),
            self.transaction_id()
        )?;
        let iter = self.iter_attributes();
        write!(f, "[")?;
        for (i, (_offset, a)) in iter.enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{a}")?;
        }
        write!(f, "]")?;
        write!(f, ")")
    }
}

/// The supported hashing algorithms for ensuring integrity of a [`Message`]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityAlgorithm {
    /// SHA-1 algorithm
    Sha1,
    /// SHA-256 algorithm
    Sha256,
}

impl<'a> Message<'a> {
    /// Create a new [`Message`] with the provided [`MessageType`] and transaction ID
    ///
    /// Note you probably want to use one of the other helper constructors instead.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// let message = Message::builder(mtype, 0.into(), MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert!(message.has_class(MessageClass::Indication));
    /// assert!(message.has_method(BINDING));
    /// ```
    pub fn builder<B: MessageWrite>(
        mtype: MessageType,
        transaction_id: TransactionId,
        mut write: B,
    ) -> B {
        let mut data = [0; 20];
        MessageHeader::new(mtype, transaction_id, 0).write_into(&mut data);
        write.push_data(&data);
        write
    }

    /// Create a new request [`Message`] of the provided method
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let data = message.finish();
    /// let message = Message::from_bytes(&data).unwrap();
    /// assert!(message.has_class(MessageClass::Request));
    /// assert!(message.has_method(BINDING));
    /// ```
    pub fn builder_request<B: MessageWrite>(method: Method, write: B) -> B {
        Message::builder(
            MessageType::from_class_method(MessageClass::Request, method),
            TransactionId::generate(),
            write,
        )
    }

    /// Create a new success [`Message`] response from the provided request
    ///
    /// # Panics
    ///
    /// When a non-request [`Message`] is passed as the original input [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #      MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let data = message.finish();
    /// let message = Message::from_bytes(&data).unwrap();
    /// let success = Message::builder_success(&message, MessageWriteVec::new()).finish();
    /// let success = Message::from_bytes(&success).unwrap();
    /// assert!(success.has_class(MessageClass::Success));
    /// assert!(success.has_method(BINDING));
    /// ```
    pub fn builder_success<B: MessageWrite>(orig: &Message, write: B) -> B {
        if !orig.has_class(MessageClass::Request) {
            panic!(
                "A success response message was attempted to be created from a non-request message"
            );
        }
        Message::builder(
            MessageType::from_class_method(MessageClass::Success, orig.method()),
            orig.transaction_id(),
            write,
        )
    }

    /// Create a new error [`Message`] response from the provided request
    ///
    /// # Panics
    ///
    /// When a non-request [`Message`] is passed as the original input [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let data = message.finish();
    /// let message = Message::from_bytes(&data).unwrap();
    /// let error = Message::builder_error(&message, MessageWriteVec::new()).finish();
    /// let error = Message::from_bytes(&error).unwrap();
    /// assert!(error.has_class(MessageClass::Error));
    /// assert!(error.has_method(BINDING));
    /// ```
    pub fn builder_error<B: MessageWrite>(orig: &Message, write: B) -> B {
        if !orig.has_class(MessageClass::Request) {
            panic!(
                "An error response message was attempted to be created from a non-request message"
            );
        }
        Message::builder(
            MessageType::from_class_method(MessageClass::Error, orig.method()),
            orig.transaction_id(),
            write,
        )
    }

    /// Retrieve the [`MessageType`] of a [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let data = message.finish();
    /// let message = Message::from_bytes(&data).unwrap();
    /// assert!(message.get_type().has_class(MessageClass::Request));
    /// assert!(message.get_type().has_method(BINDING));
    /// ```
    pub fn get_type(&self) -> MessageType {
        MessageType::try_from(&self.data[..2]).unwrap()
    }

    /// Retrieve the [`MessageClass`] of a [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.class(), MessageClass::Request);
    /// ```
    pub fn class(&self) -> MessageClass {
        self.get_type().class()
    }

    /// Returns whether the [`Message`] is of the specified [`MessageClass`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert!(message.has_class(MessageClass::Request));
    /// ```
    pub fn has_class(&self, cls: MessageClass) -> bool {
        self.class() == cls
    }

    /// Returns whether the [`Message`] is a response
    ///
    /// This means that the [`Message`] has a class of either success or error
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.is_response(), false);
    ///
    /// let error = Message::builder_error(&message, MessageWriteVec::new()).finish();
    /// let error = Message::from_bytes(&error).unwrap();
    /// assert_eq!(error.is_response(), true);
    ///
    /// let success = Message::builder_success(&message, MessageWriteVec::new()).finish();
    /// let success = Message::from_bytes(&success).unwrap();
    /// assert_eq!(success.is_response(), true);
    /// ```
    pub fn is_response(&self) -> bool {
        self.class().is_response()
    }

    /// Retrieves the method of the [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.method(), BINDING);
    /// ```
    pub fn method(&self) -> Method {
        self.get_type().method()
    }

    /// Returns whether the [`Message`] is of the specified method
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     Method, MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.has_method(BINDING), true);
    /// assert_eq!(message.has_method(Method::new(0)), false);
    /// ```
    pub fn has_method(&self, method: Method) -> bool {
        self.method() == method
    }

    /// Retrieves the 96-bit transaction ID of the [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING, TransactionId};
    /// let mtype = MessageType::from_class_method(MessageClass::Request, BINDING);
    /// let transaction_id = TransactionId::generate();
    /// let message = Message::builder(mtype, transaction_id, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.transaction_id(), transaction_id);
    /// ```
    pub fn transaction_id(&self) -> TransactionId {
        BigEndian::read_u128(&self.data[4..]).into()
    }

    /// Deserialize a `Message`
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::{RawAttribute, Attribute};
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let msg_data = vec![0, 1, 0, 8, 33, 18, 164, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232, 0, 1, 0, 1, 3, 0, 0, 0];
    /// let message = Message::from_bytes(&msg_data).unwrap();
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// let msg_attr = message.raw_attribute(1.into()).unwrap();
    /// assert_eq!(msg_attr, attr);
    /// assert_eq!(message.get_type(), MessageType::from_class_method(MessageClass::Request, BINDING));
    /// assert_eq!(message.transaction_id(), 1000.into());
    /// ```
    #[tracing::instrument(
        name = "message_from_bytes",
        level = "trace",
        skip(data),
        fields(
            data.len = data.len()
        )
    )]
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, StunParseError> {
        let orig_data = data;

        let header = MessageHeader::from_bytes(data)?;
        let mlength = header.data_length() as usize;
        if mlength + MessageHeader::LENGTH > data.len() {
            // mlength + header
            warn!(
                "malformed advertised size {} and data size {} don't match",
                mlength + 20,
                data.len()
            );
            return Err(StunParseError::Truncated {
                expected: mlength + MessageHeader::LENGTH,
                actual: data.len(),
            });
        }

        let mut data_offset = MessageHeader::LENGTH;
        let mut data = &data[MessageHeader::LENGTH..];
        let ending_attributes = [
            MessageIntegrity::TYPE,
            MessageIntegritySha256::TYPE,
            Fingerprint::TYPE,
        ];
        // XXX: maybe use small/tinyvec?
        let mut seen_ending_attributes = [AttributeType::new(0); 3];
        let mut seen_ending_len = 0;
        while !data.is_empty() {
            let attr = RawAttribute::from_bytes(data).map_err(|e| {
                warn!("failed to parse message attribute at offset {data_offset}: {e}",);
                match e {
                    StunParseError::Truncated { expected, actual } => StunParseError::Truncated {
                        expected: expected + 4 + data_offset,
                        actual: actual + 4 + data_offset,
                    },
                    StunParseError::TooLarge { expected, actual } => StunParseError::TooLarge {
                        expected: expected + 4 + data_offset,
                        actual: actual + 4 + data_offset,
                    },
                    e => e,
                }
            })?;

            // if we have seen any ending attributes, then there is only a fixed set of attributes
            // that are allowed.
            if seen_ending_len > 0 && !ending_attributes.contains(&attr.get_type()) {
                if seen_ending_attributes.contains(&Fingerprint::TYPE) {
                    warn!("unexpected attribute {} after FINGERPRINT", attr.get_type());
                    return Err(StunParseError::AttributeAfterFingerprint(attr.get_type()));
                } else {
                    // only attribute valid after MESSAGE_INTEGRITY is FINGERPRINT
                    warn!(
                        "unexpected attribute {} after MESSAGE_INTEGRITY",
                        attr.get_type()
                    );
                    return Err(StunParseError::AttributeAfterIntegrity(attr.get_type()));
                }
            }

            if ending_attributes.contains(&attr.get_type()) {
                if seen_ending_attributes.contains(&attr.get_type()) {
                    if seen_ending_attributes.contains(&Fingerprint::TYPE) {
                        warn!("unexpected attribute {} after FINGERPRINT", attr.get_type());
                        return Err(StunParseError::AttributeAfterFingerprint(attr.get_type()));
                    } else {
                        // only attribute valid after MESSAGE_INTEGRITY is FINGERPRINT
                        warn!(
                            "unexpected attribute {} after MESSAGE_INTEGRITY",
                            attr.get_type()
                        );
                        return Err(StunParseError::AttributeAfterIntegrity(attr.get_type()));
                    }
                } else {
                    seen_ending_attributes[seen_ending_len] = attr.get_type();
                    seen_ending_len += 1;
                    // need credentials to validate the integrity of the message
                }
            }
            let padded_len = attr.padded_len();
            if padded_len > data.len() {
                warn!(
                    "attribute {} extends past the end of the data",
                    attr.get_type()
                );
                return Err(StunParseError::Truncated {
                    expected: data_offset + padded_len,
                    actual: data_offset + data.len(),
                });
            }
            if attr.get_type() == Fingerprint::TYPE {
                let f = Fingerprint::from_raw_ref(&attr)?;
                let msg_fingerprint = f.fingerprint();
                let mut fingerprint_data = orig_data[..data_offset].to_vec();
                BigEndian::write_u16(
                    &mut fingerprint_data[2..4],
                    (data_offset + padded_len - MessageHeader::LENGTH) as u16,
                );
                let calculated_fingerprint = Fingerprint::compute(&fingerprint_data);
                if &calculated_fingerprint != msg_fingerprint {
                    warn!(
                        "fingerprint mismatch {:?} != {:?}",
                        calculated_fingerprint, msg_fingerprint
                    );
                    return Err(StunParseError::FingerprintMismatch);
                }
            }
            data = &data[padded_len..];
            data_offset += padded_len;
        }
        Ok(Message { data: orig_data })
    }

    /// Validates the MESSAGE_INTEGRITY attribute with the provided credentials
    ///
    /// The Original data that was used to construct this [`Message`] must be provided in order
    /// to successfully validate the [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, MessageWriteExt, BINDING, MessageIntegrityCredentials,
    /// #     LongTermCredentials, IntegrityAlgorithm};
    /// let mut message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let credentials = LongTermCredentials::new(
    ///     "user".to_owned(),
    ///     "pass".to_owned(),
    ///     "realm".to_owned()
    /// ).into();
    /// assert!(message.add_message_integrity(&credentials, IntegrityAlgorithm::Sha256).is_ok());
    /// let data = message.finish();
    /// let message = Message::from_bytes(&data).unwrap();
    /// assert!(message.validate_integrity(&credentials).is_ok());
    /// ```
    #[tracing::instrument(
        name = "message_validate_integrity",
        level = "trace",
        skip(self, credentials),
        fields(
            msg.transaction = %self.transaction_id(),
        )
    )]
    pub fn validate_integrity(
        &self,
        credentials: &MessageIntegrityCredentials,
    ) -> Result<IntegrityAlgorithm, StunParseError> {
        let raw_sha1 = self.raw_attribute(MessageIntegrity::TYPE);
        let raw_sha256 = self.raw_attribute(MessageIntegritySha256::TYPE);
        let (algo, msg_hmac) = match (raw_sha1, raw_sha256) {
            (_, Some(sha256)) => {
                let integrity = MessageIntegritySha256::try_from(&sha256)?;
                (IntegrityAlgorithm::Sha256, integrity.hmac().to_vec())
            }
            (Some(sha1), None) => {
                let integrity = MessageIntegrity::try_from(&sha1)?;
                (IntegrityAlgorithm::Sha1, integrity.hmac().to_vec())
            }
            (None, None) => return Err(StunParseError::MissingAttribute(MessageIntegrity::TYPE)),
        };

        // find the location of the original MessageIntegrity attribute: XXX: maybe encode this into
        // the attribute instead?
        let data = self.data;
        debug_assert!(data.len() >= MessageHeader::LENGTH);
        let mut data = &data[MessageHeader::LENGTH..];
        let mut data_offset = MessageHeader::LENGTH;
        while !data.is_empty() {
            let attr = RawAttribute::from_bytes(data)?;
            if algo == IntegrityAlgorithm::Sha1 && attr.get_type() == MessageIntegrity::TYPE {
                let msg = MessageIntegrity::try_from(&attr)?;
                debug_assert!(msg.hmac().as_slice() == msg_hmac);

                // HMAC is computed using all the data up to (exclusive of) the MESSAGE_INTEGRITY
                // but with a length field including the MESSAGE_INTEGRITY attribute...
                let key = credentials.make_hmac_key();
                let mut hmac_data = self.data[..data_offset].to_vec();
                BigEndian::write_u16(
                    &mut hmac_data[2..4],
                    data_offset as u16 + 24 - MessageHeader::LENGTH as u16,
                );
                MessageIntegrity::verify(
                    &hmac_data,
                    &key,
                    msg_hmac.as_slice().try_into().unwrap(),
                )?;
                return Ok(algo);
            } else if algo == IntegrityAlgorithm::Sha256
                && attr.get_type() == MessageIntegritySha256::TYPE
            {
                let msg = MessageIntegritySha256::try_from(&attr)?;
                debug_assert!(msg.hmac() == msg_hmac);

                // HMAC is computed using all the data up to (exclusive of) the MESSAGE_INTEGRITY
                // but with a length field including the MESSAGE_INTEGRITY attribute...
                let key = credentials.make_hmac_key();
                let mut hmac_data = self.data[..data_offset].to_vec();
                BigEndian::write_u16(
                    &mut hmac_data[2..4],
                    data_offset as u16 + attr.padded_len() as u16 - MessageHeader::LENGTH as u16,
                );
                MessageIntegritySha256::verify(&hmac_data, &key, &msg_hmac)?;
                return Ok(algo);
            }
            let padded_len = attr.padded_len();
            // checked when initially parsing.
            debug_assert!(padded_len <= data.len());
            data = &data[padded_len..];
            data_offset += padded_len;
        }

        // Either there is no integrity (checked earlier), or the integrity was found and checked
        // by the loop above.
        unreachable!();
    }

    /// Retrieve a `RawAttribute` from this `Message`.
    ///
    /// # Examples
    ///
    /// Retrieve a`RawAttribute`
    ///
    /// ```
    /// # use stun_types::attribute::{RawAttribute, Attribute};
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, MessageWriteExt, BINDING};
    /// let mut message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// assert!(message.add_attribute(&attr).is_ok());
    /// let message = message.finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.raw_attribute(1.into()).unwrap(), attr);
    /// ```
    pub fn raw_attribute(&self, atype: AttributeType) -> Option<RawAttribute<'_>> {
        self.raw_attribute_and_offset(atype)
            .map(|(_offset, attr)| attr)
    }

    /// Retrieve a `RawAttribute` from this `Message` with it's byte offset.
    ///
    /// The offset is from the start of the 4 byte Attribute header.
    ///
    /// # Examples
    ///
    /// Retrieve a`RawAttribute`
    ///
    /// ```
    /// # use stun_types::attribute::{RawAttribute, Attribute};
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, MessageWriteExt, BINDING};
    /// let mut message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// assert!(message.add_attribute(&attr).is_ok());
    /// let message = message.finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.raw_attribute_and_offset(1.into()).unwrap(), (20, attr));
    /// ```
    #[tracing::instrument(
        name = "message_get_raw_attribute_and_offset",
        level = "trace",
        skip(self, atype),
        fields(
            msg.transaction = %self.transaction_id(),
            attribute_type = %atype,
        )
    )]
    pub fn raw_attribute_and_offset(
        &self,
        atype: AttributeType,
    ) -> Option<(usize, RawAttribute<'_>)> {
        if let Some((offset, attr)) = self
            .iter_attributes()
            .find(|(_offset, attr)| attr.get_type() == atype)
        {
            trace!("found attribute at offset: {offset}");
            Some((offset, attr))
        } else {
            trace!("could not find attribute");
            None
        }
    }

    /// Retrieve a concrete `Attribute` from this `Message`.
    ///
    /// This will error with [`StunParseError::MissingAttribute`] if the attribute does not exist.
    /// Otherwise, other parsing errors of the data may be returned specific to the attribute
    /// implementation provided.
    ///
    /// # Examples
    ///
    /// Retrieve an `Attribute`
    ///
    /// ```
    /// # use stun_types::attribute::{Software, Attribute};
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, MessageWriteExt, BINDING};
    /// let mut message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let attr = Software::new("stun-types").unwrap();
    /// assert!(message.add_attribute(&attr).is_ok());
    /// let message = message.finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.attribute::<Software>().unwrap(), attr);
    /// ```
    pub fn attribute<A: AttributeFromRaw<'a> + AttributeStaticType>(
        &'a self,
    ) -> Result<A, StunParseError> {
        self.attribute_and_offset().map(|(_offset, attr)| attr)
    }

    /// Retrieve a concrete `Attribute` from this `Message` and it's offset in the original data.
    ///
    /// This will error with [`StunParseError::MissingAttribute`] if the attribute does not exist.
    /// Otherwise, other parsing errors of the data may be returned specific to the attribute
    /// implementation provided.
    ///
    /// The offset is from the start of the 4 byte [`Attribute`] header.
    ///
    /// # Examples
    ///
    /// Retrieve an `Attribute`
    ///
    /// ```
    /// # use stun_types::attribute::{Software, Attribute};
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, MessageWriteExt, BINDING};
    /// let mut message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let attr = Software::new("stun-types").unwrap();
    /// assert!(message.add_attribute(&attr).is_ok());
    /// let message = message.finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.attribute_and_offset::<Software>().unwrap(), (20, attr));
    /// ```
    #[tracing::instrument(
        name = "message_get_attribute_and_offset",
        level = "trace",
        err(level = tracing::Level::DEBUG),
        skip(self),
        fields(
            msg.transaction = %self.transaction_id(),
            attribute_type = %A::TYPE,
        )
    )]
    pub fn attribute_and_offset<A: AttributeFromRaw<'a> + AttributeStaticType>(
        &'a self,
    ) -> Result<(usize, A), StunParseError> {
        self.raw_attribute_and_offset(A::TYPE)
            .ok_or(StunParseError::MissingAttribute(A::TYPE))
            .and_then(|(offset, raw)| A::from_raw(raw).map(|attr| (offset, attr)))
    }

    /// Returns an iterator over the attributes (with their byte offset) in the [`Message`].
    pub fn iter_attributes(&self) -> impl Iterator<Item = (usize, RawAttribute<'_>)> {
        MessageAttributesIter::new(self.data)
    }

    /// Check that a message [`Message`] only contains required attributes that are supported and
    /// have at least some set of required attributes.  Returns an appropriate error message on
    /// failure to meet these requirements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, MessageWriteExt, BINDING};
    /// # use std::convert::TryInto;
    /// let mut builder = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let message = builder.finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// // If nothing is required, no error response is returned
    /// assert!(matches!(Message::check_attribute_types(&message, &[], &[], MessageWriteVec::new()), None));
    ///
    /// // If an atttribute is required that is not in the message, then an error response message
    /// // is generated
    /// let error_msg = Message::check_attribute_types(
    ///     &message,
    ///     &[],
    ///     &[Software::TYPE],
    ///     MessageWriteVec::new(),
    /// ).unwrap();
    /// assert!(error_msg.has_attribute(ErrorCode::TYPE));
    /// let error_msg = error_msg.finish();
    /// let error_msg = Message::from_bytes(&error_msg).unwrap();
    /// let error_code = error_msg.attribute::<ErrorCode>().unwrap();
    /// assert_eq!(error_code.code(), 400);
    ///
    /// let mut builder = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let username = Username::new("user").unwrap();
    /// builder.add_attribute(&username).unwrap();
    /// let message = builder.finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// // If a Username is in the message but is not advertised as supported then an
    /// // 'UNKNOWN-ATTRIBUTES' error response is returned
    /// let error_msg = Message::check_attribute_types(&message, &[], &[], MessageWriteVec::new()).unwrap();
    /// let error_msg = error_msg.finish();
    /// let error_msg = Message::from_bytes(&error_msg).unwrap();
    /// assert!(error_msg.is_response());
    /// assert!(error_msg.has_attribute(ErrorCode::TYPE));
    /// let error_code = error_msg.attribute::<ErrorCode>().unwrap();
    /// assert_eq!(error_code.code(), 420);
    /// assert!(error_msg.has_attribute(UnknownAttributes::TYPE));
    /// ```
    #[tracing::instrument(
        level = "trace",
        skip(msg, write),
        fields(
            msg.transaction = %msg.transaction_id(),
        )
    )]
    pub fn check_attribute_types<B: MessageWrite>(
        msg: &Message,
        supported: &[AttributeType],
        required_in_msg: &[AttributeType],
        write: B,
    ) -> Option<B> {
        // Attribute -> AttributeType
        let unsupported: Vec<AttributeType> = msg
            .iter_attributes()
            .map(|(_offset, a)| a.get_type())
            // attribute types that require comprehension but are not supported by the caller
            .filter(|at| at.comprehension_required() && !supported.contains(at))
            .collect();
        if !unsupported.is_empty() {
            warn!(
                "Message contains unknown comprehension required attributes {:?}, returning unknown attributes",
                unsupported
            );
            return Some(Message::unknown_attributes(msg, &unsupported, write));
        }
        let has_required_attribute_missing = required_in_msg
            .iter()
            // attribute types we need in the message -> failure -> Bad Request
            .any(|&at| {
                !msg.iter_attributes()
                    .map(|(_offset, a)| a.get_type())
                    .any(|a| a == at)
            });
        if has_required_attribute_missing {
            warn!("Message is missing required attributes, returning bad request");
            return Some(Message::bad_request(msg, write));
        }
        None
    }

    /// Generate an error message with an [`ErrorCode`] attribute signalling 'Unknown Attribute'
    /// and an [`UnknownAttributes`] attribute containing the attributes that are unknown.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageWriteVec, MessageWrite, BINDING};
    /// # use stun_types::attribute::*;
    /// # use std::convert::TryInto;
    /// let msg = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let msg = Message::from_bytes(&msg).unwrap();
    /// let error_msg = Message::unknown_attributes(&msg, &[Username::TYPE], MessageWriteVec::new()).finish();
    /// let error_msg = Message::from_bytes(&error_msg).unwrap();
    /// assert!(error_msg.is_response());
    /// assert!(error_msg.has_attribute(ErrorCode::TYPE));
    /// let error_code = error_msg.attribute::<ErrorCode>().unwrap();
    /// assert_eq!(error_code.code(), 420);
    /// let unknown = error_msg.attribute::<UnknownAttributes>().unwrap();
    /// assert!(unknown.has_attribute(Username::TYPE));
    /// ```
    pub fn unknown_attributes<B: MessageWrite>(
        src: &Message,
        attributes: &[AttributeType],
        write: B,
    ) -> B {
        let mut out = Message::builder_error(src, write);
        let software = Software::new("stun-types").unwrap();
        out.add_attribute(&software).unwrap();
        let error = ErrorCode::new(420, "Unknown Attributes").unwrap();
        out.add_attribute(&error).unwrap();
        let unknown = UnknownAttributes::new(attributes);
        if !attributes.is_empty() {
            out.add_attribute(&unknown).unwrap();
        }
        out
    }

    /// Generate an error message with an [`ErrorCode`] attribute signalling a 'Bad Request'
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// # use stun_types::attribute::*;
    /// # use std::convert::TryInto;
    /// let msg = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let msg = Message::from_bytes(&msg).unwrap();
    /// let error_msg = Message::bad_request(&msg, MessageWriteVec::new()).finish();
    /// let error_msg = Message::from_bytes(&error_msg).unwrap();
    /// assert!(error_msg.has_attribute(ErrorCode::TYPE));
    /// let error_code =  error_msg.attribute::<ErrorCode>().unwrap();
    /// assert_eq!(error_code.code(), 400);
    /// ```
    pub fn bad_request<B: MessageWrite>(src: &Message, write: B) -> B {
        let mut out = Message::builder_error(src, write);
        let software = Software::new("stun-types").unwrap();
        out.add_attribute(&software).unwrap();
        let error = ErrorCode::new(400, "Bad Request").unwrap();
        out.add_attribute(&error).unwrap();
        out
    }

    /// Whether this message contains an attribute of the specified type.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, MessageWriteExt, BINDING};
    /// # use stun_types::attribute::{Software, Attribute, AttributeStaticType};
    /// let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let attr = Software::new("stun-types").unwrap();
    /// assert!(msg.add_attribute(&attr).is_ok());
    /// let msg = msg.finish();
    /// let msg = Message::from_bytes(&msg).unwrap();
    /// assert!(msg.has_attribute(Software::TYPE));
    /// ```
    pub fn has_attribute(&self, atype: AttributeType) -> bool {
        self.iter_attributes()
            .any(|(_offset, attr)| attr.get_type() == atype)
    }
}
impl<'a> TryFrom<&'a [u8]> for Message<'a> {
    type Error = StunParseError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Message::from_bytes(value)
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct MessageAttributesIter<'a> {
    data: &'a [u8],
    data_i: usize,
    last_attr_type: AttributeType,
    seen_message_integrity: bool,
}

impl<'a> MessageAttributesIter<'a> {
    /// Construct an Iterator over the attributes of a [`Message`]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            data_i: MessageHeader::LENGTH,
            seen_message_integrity: false,
            last_attr_type: AttributeType::new(0),
        }
    }
}

impl<'a> Iterator for MessageAttributesIter<'a> {
    type Item = (usize, RawAttribute<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.data_i >= self.data.len() {
            return None;
        }

        let Ok(attr) = RawAttribute::from_bytes(&self.data[self.data_i..]) else {
            self.data_i = self.data.len();
            return None;
        };
        let attr_type = attr.get_type();
        let padded_len = attr.padded_len();
        self.data_i += padded_len;
        if self.seen_message_integrity {
            if attr_type == Fingerprint::TYPE {
                self.last_attr_type = attr_type;
                return Some((self.data_i - padded_len, attr));
            }
            if self.last_attr_type == MessageIntegrity::TYPE
                && attr_type == MessageIntegritySha256::TYPE
            {
                self.last_attr_type = attr_type;
                return Some((self.data_i - padded_len, attr));
            }
            return None;
        }
        if attr.get_type() == MessageIntegrity::TYPE
            || attr.get_type() == MessageIntegritySha256::TYPE
        {
            self.seen_message_integrity = true;
        }
        self.last_attr_type = attr.get_type();

        Some((self.data_i - padded_len, attr))
    }
}

#[allow(clippy::len_without_is_empty)]
/// Trait for implementing a writer for [`Message`]s.
pub trait MessageWrite {
    /// The output of this [`MessageWrite`]
    type Output;
    /// Return the maximum size of the output.  If the output data is not bound to a fixed size,
    /// `None` should be returned.
    fn max_size(&self) -> Option<usize> {
        None
    }

    /// A mutable reference to the contained data.
    fn mut_data(&mut self) -> &mut [u8];
    /// A reference to the contained data.
    fn data(&self) -> &[u8];
    /// The length of the currently written data.
    fn len(&self) -> usize;
    /// Append the provided data to the end of the output.
    fn push_data(&mut self, data: &[u8]);
    /// Write an attribute to the end of the Message.
    fn push_attribute_unchecked(&mut self, attr: &dyn AttributeWrite);

    /// Return whether this [`MessageWrite`] contains a particular attribute.
    fn has_attribute(&self, atype: AttributeType) -> bool {
        Message::from_bytes(self.data())
            .unwrap()
            .has_attribute(atype)
    }

    /// Return whether this [`MessageWrite`] contains any of the provided attributes and
    /// returns the attribute found.
    fn has_any_attribute(&self, atypes: &[AttributeType]) -> Option<AttributeType> {
        Message::from_bytes(self.data())
            .unwrap()
            .iter_attributes()
            .find_map(|(_offset, raw)| {
                if atypes.contains(&raw.get_type()) {
                    Some(raw.get_type())
                } else {
                    None
                }
            })
    }

    /// Finishes and returns the built Message.
    fn finish(self) -> Self::Output;
}

/// Extension trait for [`MessageWrite`] providing helper functions.
pub trait MessageWriteExt: MessageWrite {
    /// Retrieve the [`MessageClass`] of a [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.class(), MessageClass::Request);
    /// ```
    fn get_type(&self) -> MessageType {
        MessageType::from_bytes(self.data()).unwrap()
    }

    /// Retrieve the [`MessageClass`] of a [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.class(), MessageClass::Request);
    /// ```
    fn class(&self) -> MessageClass {
        self.get_type().class()
    }

    /// Returns whether the [`Message`] is of the specified [`MessageClass`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert!(message.has_class(MessageClass::Request));
    /// ```
    fn has_class(&self, cls: MessageClass) -> bool {
        self.class() == cls
    }

    /// Returns whether the [`Message`] is a response
    ///
    /// This means that the [`Message`] has a class of either success or error
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.is_response(), false);
    ///
    /// let error = Message::builder_error(&message, MessageWriteVec::new()).finish();
    /// let error = Message::from_bytes(&error).unwrap();
    /// assert_eq!(error.is_response(), true);
    ///
    /// let success = Message::builder_success(&message, MessageWriteVec::new()).finish();
    /// let success = Message::from_bytes(&success).unwrap();
    /// assert_eq!(success.is_response(), true);
    /// ```
    fn is_response(&self) -> bool {
        self.class().is_response()
    }

    /// Retrieves the method of the [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.method(), BINDING);
    /// ```
    fn method(&self) -> Method {
        self.get_type().method()
    }

    /// Returns whether the [`Message`] is of the specified method
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     Method, MessageWrite, BINDING};
    /// let message = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.has_method(BINDING), true);
    /// assert_eq!(message.has_method(Method::new(0)), false);
    /// ```
    fn has_method(&self, method: Method) -> bool {
        self.method() == method
    }

    /// Retrieves the 96-bit transaction ID of the [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, BINDING, TransactionId};
    /// let mtype = MessageType::from_class_method(MessageClass::Request, BINDING);
    /// let transaction_id = TransactionId::generate();
    /// let message = Message::builder(mtype, transaction_id, MessageWriteVec::new()).finish();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.transaction_id(), transaction_id);
    /// ```
    fn transaction_id(&self) -> TransactionId {
        BigEndian::read_u128(&self.data()[4..]).into()
    }

    /// Adds MESSAGE_INTEGRITY attribute to a [`Message`] using the provided credentials
    ///
    /// # Errors
    ///
    /// - If a [`MessageIntegrity`] attribute is already present
    /// - If a [`MessageIntegritySha256`] attribute is already present
    /// - If a [`Fingerprint`] attribute is already present
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWrite, MessageWriteExt, BINDING, MessageIntegrityCredentials,
    /// #     ShortTermCredentials, IntegrityAlgorithm, StunWriteError};
    /// # use stun_types::attribute::{Attribute, AttributeStaticType, MessageIntegrity,
    /// #     MessageIntegritySha256};
    /// let mut message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let credentials = ShortTermCredentials::new("pass".to_owned()).into();
    /// assert!(message.add_message_integrity(&credentials, IntegrityAlgorithm::Sha1).is_ok());
    ///
    /// // duplicate MessageIntegrity is an error
    /// assert!(matches!(
    ///     message.add_message_integrity(&credentials, IntegrityAlgorithm::Sha1),
    ///     Err(StunWriteError::AttributeExists(MessageIntegrity::TYPE)),
    /// ));
    ///
    /// // both MessageIntegrity, and MessageIntegritySha256 are allowed, however Sha256 must be
    /// // after Sha1
    /// assert!(message.add_message_integrity(&credentials, IntegrityAlgorithm::Sha256).is_ok());
    ///
    /// let data = message.finish();
    /// let message = Message::from_bytes(&data).unwrap();
    /// assert!(message.validate_integrity(&credentials).is_ok());
    /// ```
    #[tracing::instrument(
        name = "message_add_integrity",
        level = "trace",
        err,
        skip(self),
        fields(
            msg.transaction = %self.transaction_id(),
        )
    )]
    fn add_message_integrity(
        &mut self,
        credentials: &MessageIntegrityCredentials,
        algorithm: IntegrityAlgorithm,
    ) -> Result<(), StunWriteError> {
        let mut atypes = [AttributeType::new(0); 3];
        let mut i = 0;
        atypes[i] = match algorithm {
            IntegrityAlgorithm::Sha1 => MessageIntegrity::TYPE,
            IntegrityAlgorithm::Sha256 => MessageIntegritySha256::TYPE,
        };
        i += 1;
        if algorithm == IntegrityAlgorithm::Sha1 {
            atypes[i] = MessageIntegritySha256::TYPE;
            i += 1;
        }
        atypes[i] = Fingerprint::TYPE;
        i += 1;

        match self.has_any_attribute(&atypes[..i]) {
            // can't validly add generic attributes after message integrity or fingerprint
            Some(MessageIntegrity::TYPE) => {
                return Err(StunWriteError::AttributeExists(MessageIntegrity::TYPE))
            }
            Some(MessageIntegritySha256::TYPE) => {
                return Err(StunWriteError::AttributeExists(
                    MessageIntegritySha256::TYPE,
                ));
            }
            Some(Fingerprint::TYPE) => return Err(StunWriteError::FingerprintExists),
            _ => (),
        }
        match algorithm {
            IntegrityAlgorithm::Sha1 => {
                check_attribute_can_fit(self, &MessageIntegrity::new([0; 20]))?
            }
            IntegrityAlgorithm::Sha256 => {
                check_attribute_can_fit(self, &MessageIntegritySha256::new(&[0; 32]).unwrap())?
            }
        };

        add_message_integrity_unchecked(self, credentials, algorithm);

        Ok(())
    }

    /// Adds [`Fingerprint`] attribute to a [`Message`]
    ///
    /// # Errors
    ///
    /// - If a [`Fingerprint`] attribute is already present
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWriteExt, BINDING};
    /// let mut message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// assert!(message.add_fingerprint().is_ok());
    ///
    /// // duplicate FINGERPRINT is an error
    /// assert!(message.add_fingerprint().is_err());
    /// ```
    #[tracing::instrument(
        name = "message_add_fingerprint",
        level = "trace",
        skip(self),
        fields(
            msg.transaction = %self.transaction_id(),
        )
    )]
    fn add_fingerprint(&mut self) -> Result<(), StunWriteError> {
        if self.has_attribute(Fingerprint::TYPE) {
            return Err(StunWriteError::AttributeExists(Fingerprint::TYPE));
        }

        check_attribute_can_fit(self, &Fingerprint::new([0; 4]))?;
        add_fingerprint_unchecked(self);

        Ok(())
    }

    /// Add a `Attribute` to this `Message`.  Only one `AttributeType` can be added for each
    /// `Attribute.  Attempting to add multiple `Atribute`s of the same `AttributeType` will fail.
    ///
    /// # Errors
    ///
    /// - If the attribute already exists within the message
    /// - If attempting to add attributes when [`MessageIntegrity`], [`MessageIntegritySha256`] or
    /// [`Fingerprint`] atributes already exist.
    ///
    /// # Panics
    ///
    /// - if a [`MessageIntegrity`] or [`MessageIntegritySha256`] attribute is attempted to be added.  Use
    /// `Message::add_message_integrity` instead.
    /// - if a [`Fingerprint`] attribute is attempted to be added. Use
    /// `Message::add_fingerprint` instead.
    ///
    /// # Examples
    ///
    /// Add an `Attribute`
    ///
    /// ```
    /// # use stun_types::attribute::RawAttribute;
    /// # use stun_types::message::{Message, MessageType, MessageClass, MessageWriteVec,
    /// #     MessageWriteExt, BINDING};
    /// let mut message = Message::builder_request(BINDING, MessageWriteVec::new());
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// assert!(message.add_attribute(&attr).is_ok());
    /// assert!(message.add_attribute(&attr).is_err());
    /// ```
    #[tracing::instrument(
        name = "message_add_attribute",
        level = "trace",
        err,
        skip(self, attr),
        fields(
            msg.transaction = %self.transaction_id(),
        )
    )]
    fn add_attribute(&mut self, attr: &dyn AttributeWrite) -> Result<(), StunWriteError> {
        let ty = attr.get_type();
        match ty {
            MessageIntegrity::TYPE => {
                panic!("Cannot write MessageIntegrity with `add_attribute`.  Use add_message_integrity() instead");
            }
            MessageIntegritySha256::TYPE => {
                panic!("Cannot write MessageIntegritySha256 with `add_attribute`.  Use add_message_integrity() instead");
            }
            Fingerprint::TYPE => {
                panic!(
                    "Cannot write Fingerprint with `add_attribute`.  Use add_fingerprint() instead"
                );
            }
            _ => (),
        }
        match self.has_any_attribute(&[
            ty,
            MessageIntegrity::TYPE,
            MessageIntegritySha256::TYPE,
            Fingerprint::TYPE,
        ]) {
            // can't validly add generic attributes after message integrity or fingerprint
            Some(MessageIntegrity::TYPE) => return Err(StunWriteError::MessageIntegrityExists),
            Some(MessageIntegritySha256::TYPE) => {
                return Err(StunWriteError::MessageIntegrityExists)
            }
            Some(Fingerprint::TYPE) => return Err(StunWriteError::FingerprintExists),
            Some(typ) if typ == ty => return Err(StunWriteError::AttributeExists(ty)),
            _ => (),
        }
        check_attribute_can_fit(self, attr)?;
        self.push_attribute_unchecked(attr);
        Ok(())
    }
}

impl<T: MessageWrite> MessageWriteExt for T {}

/// A [`MessageWrite`] implementation that writes into a `Vec<u8>`.
#[derive(Debug, Default)]
pub struct MessageWriteVec {
    output: Vec<u8>,
    attributes: smallvec::SmallVec<[AttributeType; 16]>,
}

impl MessageWriteVec {
    /// Construct a new [`MessageWriteVec`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new [`MessageWriteVec`] with a preallocated capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            output: Vec::with_capacity(capacity),
            attributes: Default::default(),
        }
    }
}

impl std::ops::Deref for MessageWriteVec {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.output
    }
}

impl std::ops::DerefMut for MessageWriteVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.output
    }
}

impl MessageWrite for MessageWriteVec {
    type Output = Vec<u8>;

    fn mut_data(&mut self) -> &mut [u8] {
        &mut self.output
    }

    fn data(&self) -> &[u8] {
        &self.output
    }

    fn len(&self) -> usize {
        self.output.len()
    }

    fn push_data(&mut self, data: &[u8]) {
        self.output.extend(data)
    }

    fn finish(self) -> Self::Output {
        self.output
    }

    fn push_attribute_unchecked(&mut self, attr: &dyn AttributeWrite) {
        let offset = self.output.len();
        let padded_len = attr.padded_len();
        let expected = offset + padded_len;
        BigEndian::write_u16(
            &mut self.output[2..4],
            (expected - MessageHeader::LENGTH) as u16,
        );
        self.output.resize(expected, 0);
        attr.write_into_unchecked(&mut self.output[offset..]);
        self.attributes.push(attr.get_type());
    }

    fn has_attribute(&self, atype: AttributeType) -> bool {
        self.attributes.contains(&atype)
    }

    fn has_any_attribute(&self, atypes: &[AttributeType]) -> Option<AttributeType> {
        self.attributes
            .iter()
            .find(|&typ| atypes.contains(typ))
            .cloned()
    }
}

/// A [`MessageWrite`] implementation that writes into a mutable slice.
#[derive(Debug, Default)]
pub struct MessageWriteMutSlice<'a> {
    output: &'a mut [u8],
    offset: usize,
    attributes: smallvec::SmallVec<[AttributeType; 16]>,
}

impl<'a> MessageWriteMutSlice<'a> {
    /// Construct a new [`MessageWriteMutSlice`] using the provided mutbale slice.
    pub fn new(data: &'a mut [u8]) -> Self {
        Self {
            output: data,
            offset: 0,
            attributes: Default::default(),
        }
    }
}

impl std::ops::Deref for MessageWriteMutSlice<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.output
    }
}

impl std::ops::DerefMut for MessageWriteMutSlice<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.output
    }
}

impl<'a> MessageWrite for MessageWriteMutSlice<'a> {
    type Output = usize;

    fn max_size(&self) -> Option<usize> {
        Some(self.output.len())
    }

    fn mut_data(&mut self) -> &mut [u8] {
        &mut self.output[..self.offset]
    }

    fn data(&self) -> &[u8] {
        &self.output[..self.offset]
    }

    fn len(&self) -> usize {
        self.offset
    }

    fn push_data(&mut self, data: &[u8]) {
        let len = data.len();
        self.output[self.offset..self.offset + len].copy_from_slice(data);
        self.offset += len;
    }

    fn push_attribute_unchecked(&mut self, attr: &dyn AttributeWrite) {
        let padded_len = attr.padded_len();
        let expected = self.offset + padded_len;
        BigEndian::write_u16(
            &mut self.output[2..4],
            (expected - MessageHeader::LENGTH) as u16,
        );
        attr.write_into(&mut self.output[self.offset..self.offset + padded_len])
            .unwrap();
        self.offset += padded_len;
    }

    fn finish(self) -> Self::Output {
        self.offset
    }

    fn has_attribute(&self, atype: AttributeType) -> bool {
        self.attributes.contains(&atype)
    }

    fn has_any_attribute(&self, atypes: &[AttributeType]) -> Option<AttributeType> {
        self.attributes
            .iter()
            .find(|&typ| atypes.contains(typ))
            .cloned()
    }
}

fn check_attribute_can_fit<O, T: MessageWrite<Output = O> + ?Sized>(
    this: &mut T,
    attr: &dyn AttributeWrite,
) -> Result<usize, StunWriteError> {
    let len = attr.padded_len();
    let out_data = this.data();
    if out_data.len() < MessageHeader::LENGTH {
        return Err(StunWriteError::TooSmall {
            expected: 20,
            actual: out_data.len(),
        });
    }
    let expected = BigEndian::read_u16(&out_data[2..4]) as usize + MessageHeader::LENGTH + len;
    if let Some(max) = this.max_size() {
        if max < expected {
            return Err(StunWriteError::TooSmall {
                expected,
                actual: max,
            });
        }
    }
    Ok(expected)
}

fn add_message_integrity_unchecked<O, T: MessageWrite<Output = O> + ?Sized>(
    this: &mut T,
    credentials: &MessageIntegrityCredentials,
    algorithm: IntegrityAlgorithm,
) {
    let key = credentials.make_hmac_key();
    // message-integrity is computed using all the data up to (exclusive of) the
    // MESSAGE-INTEGRITY but with a length field including the MESSAGE-INTEGRITY attribute...
    match algorithm {
        IntegrityAlgorithm::Sha1 => {
            this.push_attribute_unchecked(&MessageIntegrity::new([0; 20]));
            let len = this.len();
            let data = this.mut_data();
            let integrity = MessageIntegrity::compute(&data[..len - 24], &key).unwrap();
            data[len - 20..].copy_from_slice(&integrity);
        }
        IntegrityAlgorithm::Sha256 => {
            this.push_attribute_unchecked(&MessageIntegritySha256::new(&[0; 32]).unwrap());
            let len = this.len();
            let data = this.mut_data();
            let integrity = MessageIntegritySha256::compute(&data[..len - 36], &key).unwrap();
            data[len - 32..].copy_from_slice(&integrity);
        }
    }
}

fn add_fingerprint_unchecked<O, T: MessageWrite<Output = O> + ?Sized>(this: &mut T) {
    // fingerprint is computed using all the data up to (exclusive of) the FINGERPRINT
    // but with a length field including the FINGERPRINT attribute...
    this.push_attribute_unchecked(&Fingerprint::new([0; 4]));
    let len = this.len();
    let data = this.mut_data();
    let fingerprint = Fingerprint::compute(&data[..len - 8]);
    let fingerprint = Fingerprint::new(fingerprint);
    fingerprint.write_into(&mut data[len - 8..]).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_type_roundtrip() {
        let _log = crate::tests::test_init_log();
        /* validate that all methods/classes survive a roundtrip */
        for m in 0..0xfff {
            let m = Method::new(m);
            let classes = vec![
                MessageClass::Request,
                MessageClass::Indication,
                MessageClass::Success,
                MessageClass::Error,
            ];
            for c in classes {
                let mtype = MessageType::from_class_method(c, m);
                assert_eq!(mtype.class(), c);
                assert_eq!(mtype.method(), m);
                let bytes = mtype.to_bytes();
                let ptype = MessageType::from_bytes(&bytes).unwrap();
                assert_eq!(mtype, ptype);
            }
        }
    }

    #[test]
    fn msg_type_not_stun() {
        assert!(matches!(
            MessageType::from_bytes(&[0xc0, 0x00]),
            Err(StunParseError::NotStun)
        ));
    }

    #[test]
    fn msg_roundtrip() {
        let _log = crate::tests::test_init_log();
        /* validate that all methods/classes survive a roundtrip */
        for m in (0x009..0x4ff).step_by(0x123) {
            let m = Method::new(m);
            let classes = vec![
                MessageClass::Request,
                MessageClass::Indication,
                MessageClass::Success,
                MessageClass::Error,
            ];
            for c in classes {
                let mtype = MessageType::from_class_method(c, m);
                for tid in (0x18..0xff_ffff_ffff_ffff_ffff).step_by(0xfedc_ba98_7654_3210) {
                    let mut msg = Message::builder(mtype, tid.into(), MessageWriteVec::default());
                    let attr = RawAttribute::new(1.into(), &[3]);
                    assert!(msg.add_attribute(&attr).is_ok());
                    let data = msg.finish();

                    let msg = Message::from_bytes(&data).unwrap();
                    let msg_attr = msg.raw_attribute(1.into()).unwrap();
                    assert_eq!(msg_attr, attr);
                    assert_eq!(msg.get_type(), mtype);
                    assert_eq!(msg.transaction_id(), tid.into());
                }
            }
        }
    }

    #[test]
    fn unknown_attributes() {
        let _log = crate::tests::test_init_log();
        let src = Message::builder_request(BINDING, MessageWriteVec::default()).finish();
        let src = Message::from_bytes(&src).unwrap();
        let msg =
            Message::unknown_attributes(&src, &[Software::TYPE], MessageWriteVec::new()).finish();
        let msg = Message::from_bytes(&msg).unwrap();
        assert_eq!(msg.transaction_id(), src.transaction_id());
        assert_eq!(msg.class(), MessageClass::Error);
        assert_eq!(msg.method(), src.method());
        let err = msg.attribute::<ErrorCode>().unwrap();
        assert_eq!(err.code(), 420);
        let unknown_attrs = msg.attribute::<UnknownAttributes>().unwrap();
        assert!(unknown_attrs.has_attribute(Software::TYPE));
    }

    #[test]
    fn bad_request() {
        let _log = crate::tests::test_init_log();
        let src = Message::builder_request(BINDING, MessageWriteVec::new()).finish();
        let src = Message::from_bytes(&src).unwrap();
        let msg = Message::bad_request(&src, MessageWriteVec::new()).finish();
        let msg = Message::from_bytes(&msg).unwrap();
        assert_eq!(msg.transaction_id(), src.transaction_id());
        assert_eq!(msg.class(), MessageClass::Error);
        assert_eq!(msg.method(), src.method());
        let err = msg.attribute::<ErrorCode>().unwrap();
        assert_eq!(err.code(), 400);
    }

    #[test]
    fn fingerprint() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let software = Software::new("s").unwrap();
        msg.add_attribute(&software).unwrap();
        msg.add_fingerprint().unwrap();
        let bytes = msg.finish();
        // validates the fingerprint of the data when available
        let new_msg = Message::from_bytes(&bytes).unwrap();
        let (offset, software) = new_msg.attribute_and_offset::<Software>().unwrap();
        assert_eq!(software.software(), "s");
        assert_eq!(offset, 20);
        let (offset, _new_fingerprint) = new_msg.attribute_and_offset::<Fingerprint>().unwrap();
        assert_eq!(offset, 28);
    }

    #[test]
    fn integrity() {
        let _log = crate::tests::test_init_log();
        for algorithm in [IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256] {
            let credentials = ShortTermCredentials::new("secret".to_owned()).into();
            let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
            let software = Software::new("s").unwrap();
            msg.add_attribute(&software).unwrap();
            msg.add_message_integrity(&credentials, algorithm).unwrap();
            let bytes = msg.finish();
            // validates the fingerprint of the data when available
            let new_msg = Message::from_bytes(&bytes).unwrap();
            new_msg.validate_integrity(&credentials).unwrap();
            let (offset, software) = new_msg.attribute_and_offset::<Software>().unwrap();
            assert_eq!(software.software(), "s");
            assert_eq!(offset, 20);
        }
    }

    #[test]
    fn write_into_short_destination() {
        let _log = crate::tests::test_init_log();
        const LEN: usize = MessageHeader::LENGTH + 8;
        let mut data = [0; LEN - 1];
        let mut msg = Message::builder_request(BINDING, MessageWriteMutSlice::new(&mut data));
        let software = Software::new("s").unwrap();
        assert!(
            matches!(msg.add_attribute(&software), Err(StunWriteError::TooSmall { expected, actual }) if expected == LEN && actual == LEN - 1)
        );
    }

    #[test]
    fn add_duplicate_integrity() {
        let _log = crate::tests::test_init_log();
        let credentials = ShortTermCredentials::new("secret".to_owned()).into();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_message_integrity(&credentials, IntegrityAlgorithm::Sha1)
            .unwrap();
        assert!(matches!(
            msg.add_message_integrity(&credentials, IntegrityAlgorithm::Sha1),
            Err(StunWriteError::AttributeExists(MessageIntegrity::TYPE))
        ));
        msg.add_message_integrity(&credentials, IntegrityAlgorithm::Sha256)
            .unwrap();
        assert!(matches!(
            msg.add_message_integrity(&credentials, IntegrityAlgorithm::Sha256),
            Err(StunWriteError::AttributeExists(
                MessageIntegritySha256::TYPE
            ))
        ));
        let software = Software::new("s").unwrap();
        assert!(matches!(
            msg.add_attribute(&software),
            Err(StunWriteError::MessageIntegrityExists)
        ));
    }

    #[test]
    fn add_sha1_integrity_after_sha256() {
        let _log = crate::tests::test_init_log();
        let credentials = ShortTermCredentials::new("secret".to_owned()).into();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_message_integrity(&credentials, IntegrityAlgorithm::Sha256)
            .unwrap();
        assert!(matches!(
            msg.add_message_integrity(&credentials, IntegrityAlgorithm::Sha1),
            Err(StunWriteError::AttributeExists(
                MessageIntegritySha256::TYPE
            ))
        ));
    }

    #[test]
    fn add_attribute_after_integrity() {
        let _log = crate::tests::test_init_log();
        for algorithm in [IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256] {
            let credentials = ShortTermCredentials::new("secret".to_owned()).into();
            let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
            msg.add_message_integrity(&credentials, algorithm).unwrap();
            let software = Software::new("s").unwrap();
            assert!(matches!(
                msg.add_attribute(&software),
                Err(StunWriteError::MessageIntegrityExists)
            ));
        }
    }

    #[test]
    fn add_raw_attribute_after_integrity() {
        let _log = crate::tests::test_init_log();
        for algorithm in [IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256] {
            let credentials = ShortTermCredentials::new("secret".to_owned()).into();
            let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
            msg.add_message_integrity(&credentials, algorithm).unwrap();
            let software = Software::new("s").unwrap();
            let raw = software.to_raw();
            assert!(matches!(
                msg.add_attribute(&raw),
                Err(StunWriteError::MessageIntegrityExists)
            ));
        }
    }

    #[test]
    fn add_integrity_after_fingerprint() {
        let _log = crate::tests::test_init_log();
        for algorithm in [IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256] {
            let credentials = ShortTermCredentials::new("secret".to_owned()).into();
            let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
            msg.add_fingerprint().unwrap();
            assert!(matches!(
                msg.add_message_integrity(&credentials, algorithm),
                Err(StunWriteError::FingerprintExists)
            ));
        }
    }

    #[test]
    fn duplicate_add_attribute() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let software = Software::new("s").unwrap();
        msg.add_attribute(&software).unwrap();
        assert!(matches!(
            msg.add_attribute(&software),
            Err(StunWriteError::AttributeExists(ty)) if ty == Software::TYPE
        ));
    }

    #[test]
    fn duplicate_add_raw_attribute() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let software = Software::new("s").unwrap();
        let raw = software.to_raw();
        msg.add_attribute(&raw).unwrap();
        assert!(matches!(
            msg.add_attribute(&raw),
            Err(StunWriteError::AttributeExists(ty)) if ty == Software::TYPE
        ));
    }

    #[test]
    fn duplicate_fingerprint() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_fingerprint().unwrap();
        assert!(matches!(
            msg.add_fingerprint(),
            Err(StunWriteError::AttributeExists(Fingerprint::TYPE))
        ));
    }

    #[test]
    fn parse_invalid_fingerprint() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_fingerprint().unwrap();
        let mut bytes = msg.finish();
        bytes[24] = 0x80;
        bytes[25] = 0x80;
        bytes[26] = 0x80;
        bytes[27] = 0x80;
        assert!(matches!(
            Message::from_bytes(&bytes),
            Err(StunParseError::FingerprintMismatch)
        ));
    }

    #[test]
    fn parse_wrong_magic() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_fingerprint().unwrap();
        let mut bytes = msg.finish();
        bytes[4] = 0x80;
        assert!(matches!(
            Message::from_bytes(&bytes),
            Err(StunParseError::NotStun)
        ));
    }

    #[test]
    fn parse_attribute_after_integrity() {
        let _log = crate::tests::test_init_log();
        for algorithm in [IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256] {
            let credentials = ShortTermCredentials::new("secret".to_owned()).into();
            let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
            msg.add_message_integrity(&credentials, algorithm).unwrap();
            let mut bytes = msg.finish();
            let software = Software::new("s").unwrap();
            let software_bytes = RawAttribute::from(&software).to_bytes();
            let software_len = software_bytes.len();
            bytes.extend(software_bytes);
            bytes[3] += software_len as u8;
            assert!(matches!(
                Message::from_bytes(&bytes),
                Err(StunParseError::AttributeAfterIntegrity(Software::TYPE))
            ));
        }
    }

    #[test]
    fn parse_duplicate_integrity_after_integrity() {
        let _log = crate::tests::test_init_log();
        for algorithm in [IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256] {
            let credentials = ShortTermCredentials::new("secret".to_owned()).into();
            let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
            msg.add_message_integrity(&credentials, algorithm).unwrap();
            // duplicate integrity attribute. Don't do this in real code!
            add_message_integrity_unchecked(&mut msg, &credentials, algorithm);
            let bytes = msg.finish();
            let integrity_type = match algorithm {
                IntegrityAlgorithm::Sha1 => MessageIntegrity::TYPE,
                IntegrityAlgorithm::Sha256 => MessageIntegritySha256::TYPE,
            };
            let Err(StunParseError::AttributeAfterIntegrity(err_integrity_type)) =
                Message::from_bytes(&bytes)
            else {
                unreachable!();
            };
            assert_eq!(integrity_type, err_integrity_type);
        }
    }

    #[test]
    fn parse_attribute_after_fingerprint() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_fingerprint().unwrap();
        let mut bytes = msg.finish();
        let software = Software::new("s").unwrap();
        let software_bytes = RawAttribute::from(&software).to_bytes();
        let software_len = software_bytes.len();
        bytes.extend(software_bytes);
        bytes[3] += software_len as u8;
        assert!(matches!(
            Message::from_bytes(&bytes),
            Err(StunParseError::AttributeAfterFingerprint(Software::TYPE))
        ));
    }

    #[test]
    fn parse_duplicate_fingerprint_after_fingerprint() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_fingerprint().unwrap();
        add_fingerprint_unchecked(&mut msg);
        let bytes = msg.finish();
        assert!(matches!(
            Message::from_bytes(&bytes),
            Err(StunParseError::AttributeAfterFingerprint(Fingerprint::TYPE))
        ));
    }

    #[test]
    fn add_attribute_after_fingerprint() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_fingerprint().unwrap();
        let software = Software::new("s").unwrap();
        assert!(matches!(
            msg.add_attribute(&software),
            Err(StunWriteError::FingerprintExists)
        ));
    }

    #[test]
    fn add_raw_attribute_after_fingerprint() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_fingerprint().unwrap();
        let software = Software::new("s").unwrap();
        let raw = software.to_raw();
        assert!(matches!(
            msg.add_attribute(&raw),
            Err(StunWriteError::FingerprintExists)
        ));
    }

    #[test]
    fn parse_truncated_message_header() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_fingerprint().unwrap();
        let bytes = msg.finish();
        assert!(matches!(
            Message::from_bytes(&bytes[..8]),
            Err(StunParseError::Truncated {
                expected: 20,
                actual: 8
            })
        ));
    }

    #[test]
    fn parse_truncated_message() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_fingerprint().unwrap();
        let bytes = msg.finish();
        assert!(matches!(
            Message::from_bytes(&bytes[..24]),
            Err(StunParseError::Truncated {
                expected: 28,
                actual: 24
            })
        ));
    }

    #[test]
    fn parse_truncated_message_attribute() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        msg.add_fingerprint().unwrap();
        let mut bytes = msg.finish();
        // rewrite message header to support the truncated length, but not the attribute.
        bytes[3] = 4;
        assert!(matches!(
            Message::from_bytes(&bytes[..24]),
            Err(StunParseError::Truncated {
                expected: 28,
                actual: 24
            })
        ));
    }

    #[test]
    fn valid_attributes() {
        let _log = crate::tests::test_init_log();
        let mut src = Message::builder_request(BINDING, MessageWriteVec::new());
        let username = Username::new("123").unwrap();
        src.add_attribute(&username).unwrap();
        let priority = Priority::new(123);
        src.add_attribute(&priority).unwrap();
        let src = src.finish();
        let src = Message::from_bytes(&src).unwrap();

        // success case
        let res = Message::check_attribute_types(
            &src,
            &[Username::TYPE, Priority::TYPE],
            &[Username::TYPE],
            MessageWriteVec::new(),
        );
        assert!(res.is_none());

        // fingerprint required but not present
        let res = Message::check_attribute_types(
            &src,
            &[Username::TYPE, Priority::TYPE],
            &[Fingerprint::TYPE],
            MessageWriteVec::new(),
        );
        assert!(res.is_some());
        let res = res.unwrap();
        let res = res.finish();
        let res = Message::from_bytes(&res).unwrap();
        assert!(res.has_class(MessageClass::Error));
        assert!(res.has_method(src.method()));
        let err = res.attribute::<ErrorCode>().unwrap();
        assert_eq!(err.code(), 400);

        // priority unsupported
        let res =
            Message::check_attribute_types(&src, &[Username::TYPE], &[], MessageWriteVec::new());
        assert!(res.is_some());
        let res = res.unwrap();
        let data = res.finish();
        let res = Message::from_bytes(&data).unwrap();
        assert!(res.has_class(MessageClass::Error));
        assert!(res.has_method(src.method()));
        let err = res.attribute::<ErrorCode>().unwrap();
        assert_eq!(err.code(), 420);
        let unknown = res.attribute::<UnknownAttributes>().unwrap();
        assert!(unknown.has_attribute(Priority::TYPE));
    }

    #[test]
    #[should_panic(expected = "created from a non-request message")]
    fn builder_success_panic() {
        let _log = crate::tests::test_init_log();
        let msg = Message::builder(
            MessageType::from_class_method(MessageClass::Indication, BINDING),
            TransactionId::generate(),
            MessageWriteVec::new(),
        )
        .finish();
        let msg = Message::from_bytes(&msg).unwrap();
        let _builder = Message::builder_success(&msg, MessageWriteVec::new());
    }

    #[test]
    #[should_panic(expected = "created from a non-request message")]
    fn builder_error_panic() {
        let _log = crate::tests::test_init_log();
        let msg = Message::builder(
            MessageType::from_class_method(MessageClass::Indication, BINDING),
            TransactionId::generate(),
            MessageWriteVec::new(),
        )
        .finish();
        let msg = Message::from_bytes(&msg).unwrap();
        let _builder = Message::builder_error(&msg, MessageWriteVec::new());
    }

    #[test]
    #[should_panic(expected = "Use add_message_integrity() instead")]
    fn builder_add_attribute_integrity_panic() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let hmac = [2; 20];
        let integrity = MessageIntegrity::new(hmac);
        msg.add_attribute(&integrity).unwrap();
    }

    #[test]
    #[should_panic(expected = "Use add_message_integrity() instead")]
    fn builder_add_raw_attribute_integrity_panic() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let hmac = [2; 20];
        let integrity = MessageIntegrity::new(hmac);
        let raw = integrity.to_raw();
        msg.add_attribute(&raw).unwrap();
    }

    #[test]
    #[should_panic(expected = "Use add_message_integrity() instead")]
    fn builder_add_attribute_integrity_sha256_panic() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let hmac = [2; 16];
        let integrity = MessageIntegritySha256::new(&hmac).unwrap();
        msg.add_attribute(&integrity).unwrap();
    }

    #[test]
    #[should_panic(expected = "Use add_message_integrity() instead")]
    fn builder_add_raw_attribute_integrity_sha256_panic() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let hmac = [2; 16];
        let integrity = MessageIntegritySha256::new(&hmac).unwrap();
        let raw = integrity.to_raw();
        msg.add_attribute(&raw).unwrap();
    }

    #[test]
    #[should_panic(expected = "Use add_fingerprint() instead")]
    fn builder_add_attribute_fingerprint_panic() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let fingerprint = [2; 4];
        let fingerprint = Fingerprint::new(fingerprint);
        msg.add_attribute(&fingerprint).unwrap();
    }

    #[test]
    #[should_panic(expected = "Use add_fingerprint() instead")]
    fn builder_add_raw_attribute_fingerprint_panic() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let fingerprint = [2; 4];
        let fingerprint = Fingerprint::new(fingerprint);
        let raw = fingerprint.to_raw();
        msg.add_attribute(&raw).unwrap();
    }

    #[test]
    fn rfc5769_vector1() {
        let _log = crate::tests::test_init_log();
        // https://tools.ietf.org/html/rfc5769#section-2.1
        let data = vec![
            0x00, 0x01, 0x00, 0x58, // Request type message length
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0xb7, 0xe7, 0xa7, 0x01, // }
            0xbc, 0x34, 0xd6, 0x86, // } Transaction ID
            0xfa, 0x87, 0xdf, 0xae, // }
            0x80, 0x22, 0x00, 0x10, // SOFTWARE header
            0x53, 0x54, 0x55, 0x4e, //   }
            0x20, 0x74, 0x65, 0x73, //   }  User-agent...
            0x74, 0x20, 0x63, 0x6c, //   }  ...name
            0x69, 0x65, 0x6e, 0x74, //   }
            0x00, 0x24, 0x00, 0x04, // PRIORITY header
            0x6e, 0x00, 0x01, 0xff, //   PRIORITY value
            0x80, 0x29, 0x00, 0x08, // ICE_CONTROLLED header
            0x93, 0x2f, 0xf9, 0xb1, //   Pseudo random number
            0x51, 0x26, 0x3b, 0x36, //   ... for tie breaker
            0x00, 0x06, 0x00, 0x09, // USERNAME header
            0x65, 0x76, 0x74, 0x6a, //   Username value
            0x3a, 0x68, 0x36, 0x76, //   (9 bytes)
            0x59, 0x20, 0x20, 0x20, //   (3 bytes padding)
            0x00, 0x08, 0x00, 0x14, // MESSAGE-INTEGRITY header
            0x9a, 0xea, 0xa7, 0x0c, //   }
            0xbf, 0xd8, 0xcb, 0x56, //   }
            0x78, 0x1e, 0xf2, 0xb5, //   } HMAC-SHA1 fingerprint
            0xb2, 0xd3, 0xf2, 0x49, //   }
            0xc1, 0xb5, 0x71, 0xa2, //   }
            0x80, 0x28, 0x00, 0x04, // FINGERPRINT header
            0xe5, 0x7a, 0x3b, 0xcf, //   CRC32 fingerprint
        ];
        let msg = Message::from_bytes(&data).unwrap();
        assert!(msg.has_class(MessageClass::Request));
        assert!(msg.has_method(BINDING));
        assert_eq!(msg.transaction_id(), 0xb7e7_a701_bc34_d686_fa87_dfae.into());

        let mut builder = Message::builder(
            MessageType::from_class_method(MessageClass::Request, BINDING),
            msg.transaction_id(),
            MessageWriteVec::new(),
        );

        // SOFTWARE
        assert!(msg.has_attribute(Software::TYPE));
        let raw = msg.raw_attribute(Software::TYPE).unwrap();
        assert!(Software::try_from(&raw).is_ok());
        let software = Software::try_from(&raw).unwrap();
        assert_eq!(software.software(), "STUN test client");
        builder.add_attribute(&software).unwrap();

        // PRIORITY
        assert!(msg.has_attribute(Priority::TYPE));
        let raw = msg.raw_attribute(Priority::TYPE).unwrap();
        assert!(Priority::try_from(&raw).is_ok());
        let priority = Priority::try_from(&raw).unwrap();
        assert_eq!(priority.priority(), 0x6e0001ff);
        builder.add_attribute(&priority).unwrap();

        // ICE-CONTROLLED
        assert!(msg.has_attribute(IceControlled::TYPE));
        let raw = msg.raw_attribute(IceControlled::TYPE).unwrap();
        assert!(IceControlled::try_from(&raw).is_ok());
        let ice = IceControlled::try_from(&raw).unwrap();
        assert_eq!(ice.tie_breaker(), 0x932f_f9b1_5126_3b36);
        builder.add_attribute(&ice).unwrap();

        // USERNAME
        assert!(msg.has_attribute(Username::TYPE));
        let raw = msg.raw_attribute(Username::TYPE).unwrap();
        assert!(Username::try_from(&raw).is_ok());
        let username = Username::try_from(&raw).unwrap();
        assert_eq!(username.username(), "evtj:h6vY");
        builder.add_attribute(&username).unwrap();

        // MESSAGE_INTEGRITY
        let credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
            password: "VOkJxbRl1RmTxUk/WvJxBt".to_owned(),
        });
        assert!(matches!(
            msg.validate_integrity(&credentials),
            Ok(IntegrityAlgorithm::Sha1)
        ));
        builder
            .add_message_integrity(&credentials, IntegrityAlgorithm::Sha1)
            .unwrap();

        // FINGERPRINT is checked by Message::from_bytes() when present
        assert!(msg.has_attribute(Fingerprint::TYPE));
        builder.add_fingerprint().unwrap();

        // assert that we produce the same output as we parsed in this case
        let mut msg_data = builder.finish();
        // match the padding bytes with the original
        msg_data[73] = 0x20;
        msg_data[74] = 0x20;
        msg_data[75] = 0x20;
        // as a result of the padding difference, the message integrity and fingerpinrt values will
        // be different
        assert_eq!(msg_data[..80], data[..80]);
    }

    #[test]
    fn rfc5769_vector2() {
        let _log = crate::tests::test_init_log();
        // https://tools.ietf.org/html/rfc5769#section-2.2
        let data = vec![
            0x01, 0x01, 0x00, 0x3c, // Response type message length
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0xb7, 0xe7, 0xa7, 0x01, // }
            0xbc, 0x34, 0xd6, 0x86, // }  Transaction ID
            0xfa, 0x87, 0xdf, 0xae, // }
            0x80, 0x22, 0x00, 0x0b, // SOFTWARE attribute header
            0x74, 0x65, 0x73, 0x74, //   }
            0x20, 0x76, 0x65, 0x63, //   }  UTF-8 server name
            0x74, 0x6f, 0x72, 0x20, //   }
            0x00, 0x20, 0x00, 0x08, // XOR-MAPPED-ADDRESS attribute header
            0x00, 0x01, 0xa1, 0x47, //   Address family (IPv4) and xor'd mapped port number
            0xe1, 0x12, 0xa6, 0x43, //   Xor'd mapped IPv4 address
            0x00, 0x08, 0x00, 0x14, //   MESSAGE-INTEGRITY attribute header
            0x2b, 0x91, 0xf5, 0x99, // }
            0xfd, 0x9e, 0x90, 0xc3, // }
            0x8c, 0x74, 0x89, 0xf9, // }  HMAC-SHA1 fingerprint
            0x2a, 0xf9, 0xba, 0x53, // }
            0xf0, 0x6b, 0xe7, 0xd7, // }
            0x80, 0x28, 0x00, 0x04, //  FINGERPRINT attribute header
            0xc0, 0x7d, 0x4c, 0x96, //  CRC32 fingerprint
        ];

        let msg = Message::from_bytes(&data).unwrap();
        assert!(msg.has_class(MessageClass::Success));
        assert!(msg.has_method(BINDING));
        assert_eq!(msg.transaction_id(), 0xb7e7_a701_bc34_d686_fa87_dfae.into());
        let mut builder = Message::builder(
            MessageType::from_class_method(MessageClass::Success, BINDING),
            msg.transaction_id(),
            MessageWriteVec::new(),
        );

        // SOFTWARE
        assert!(msg.has_attribute(Software::TYPE));
        let raw = msg.raw_attribute(Software::TYPE).unwrap();
        assert!(Software::try_from(&raw).is_ok());
        let software = Software::try_from(&raw).unwrap();
        assert_eq!(software.software(), "test vector");
        builder.add_attribute(&software).unwrap();

        // XOR_MAPPED_ADDRESS
        assert!(msg.has_attribute(XorMappedAddress::TYPE));
        let raw = msg.raw_attribute(XorMappedAddress::TYPE).unwrap();
        assert!(XorMappedAddress::try_from(&raw).is_ok());
        let xor_mapped_addres = XorMappedAddress::try_from(&raw).unwrap();
        assert_eq!(
            xor_mapped_addres.addr(msg.transaction_id()),
            "192.0.2.1:32853".parse().unwrap()
        );
        builder.add_attribute(&xor_mapped_addres).unwrap();

        // MESSAGE_INTEGRITY
        let credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
            password: "VOkJxbRl1RmTxUk/WvJxBt".to_owned(),
        });
        let ret = msg.validate_integrity(&credentials);
        warn!("{:?}", ret);
        assert!(matches!(ret, Ok(IntegrityAlgorithm::Sha1)));
        builder
            .add_message_integrity(&credentials, IntegrityAlgorithm::Sha1)
            .unwrap();

        // FINGERPRINT is checked by Message::from_bytes() when present
        assert!(msg.has_attribute(Fingerprint::TYPE));
        builder.add_fingerprint().unwrap();

        // assert that we produce the same output as we parsed in this case
        let mut msg_data = builder.finish();
        // match the padding bytes with the original
        msg_data[35] = 0x20;
        assert_eq!(msg_data[..52], data[..52]);
    }

    #[test]
    fn rfc5769_vector3() {
        let _log = crate::tests::test_init_log();
        // https://tools.ietf.org/html/rfc5769#section-2.3
        let data = vec![
            0x01, 0x01, 0x00, 0x48, // Response type and message length
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0xb7, 0xe7, 0xa7, 0x01, // }
            0xbc, 0x34, 0xd6, 0x86, // }  Transaction ID
            0xfa, 0x87, 0xdf, 0xae, // }
            0x80, 0x22, 0x00, 0x0b, //    SOFTWARE attribute header
            0x74, 0x65, 0x73, 0x74, // }
            0x20, 0x76, 0x65, 0x63, // }  UTF-8 server name
            0x74, 0x6f, 0x72, 0x20, // }
            0x00, 0x20, 0x00, 0x14, //    XOR-MAPPED-ADDRESS attribute header
            0x00, 0x02, 0xa1, 0x47, //    Address family (IPv6) and xor'd mapped port number
            0x01, 0x13, 0xa9, 0xfa, // }
            0xa5, 0xd3, 0xf1, 0x79, // }  Xor'd mapped IPv6 address
            0xbc, 0x25, 0xf4, 0xb5, // }
            0xbe, 0xd2, 0xb9, 0xd9, // }
            0x00, 0x08, 0x00, 0x14, //    MESSAGE-INTEGRITY attribute header
            0xa3, 0x82, 0x95, 0x4e, // }
            0x4b, 0xe6, 0x7b, 0xf1, // }
            0x17, 0x84, 0xc9, 0x7c, // }  HMAC-SHA1 fingerprint
            0x82, 0x92, 0xc2, 0x75, // }
            0xbf, 0xe3, 0xed, 0x41, // }
            0x80, 0x28, 0x00, 0x04, //    FINGERPRINT attribute header
            0xc8, 0xfb, 0x0b, 0x4c, //    CRC32 fingerprint
        ];

        let msg = Message::from_bytes(&data).unwrap();
        assert!(msg.has_class(MessageClass::Success));
        assert!(msg.has_method(BINDING));
        assert_eq!(msg.transaction_id(), 0xb7e7_a701_bc34_d686_fa87_dfae.into());
        let mut builder = Message::builder(
            MessageType::from_class_method(MessageClass::Success, BINDING),
            msg.transaction_id(),
            MessageWriteVec::new(),
        );

        // SOFTWARE
        assert!(msg.has_attribute(Software::TYPE));
        let raw = msg.raw_attribute(Software::TYPE).unwrap();
        assert!(Software::try_from(&raw).is_ok());
        let software = Software::try_from(&raw).unwrap();
        assert_eq!(software.software(), "test vector");
        builder.add_attribute(&software).unwrap();

        // XOR_MAPPED_ADDRESS
        assert!(msg.has_attribute(XorMappedAddress::TYPE));
        let raw = msg.raw_attribute(XorMappedAddress::TYPE).unwrap();
        assert!(XorMappedAddress::try_from(&raw).is_ok());
        let xor_mapped_addres = XorMappedAddress::try_from(&raw).unwrap();
        assert_eq!(
            xor_mapped_addres.addr(msg.transaction_id()),
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                .parse()
                .unwrap()
        );
        builder.add_attribute(&xor_mapped_addres).unwrap();

        // MESSAGE_INTEGRITY
        let credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
            password: "VOkJxbRl1RmTxUk/WvJxBt".to_owned(),
        });
        assert!(matches!(
            msg.validate_integrity(&credentials),
            Ok(IntegrityAlgorithm::Sha1)
        ));
        builder
            .add_message_integrity(&credentials, IntegrityAlgorithm::Sha1)
            .unwrap();

        // FINGERPRINT is checked by Message::from_bytes() when present
        assert!(msg.has_attribute(Fingerprint::TYPE));
        builder.add_fingerprint().unwrap();

        // assert that we produce the same output as we parsed in this case
        let mut msg_data = builder.finish();
        // match the padding bytes with the original
        msg_data[35] = 0x20;
        assert_eq!(msg_data[..64], data[..64]);
    }

    #[test]
    fn rfc5769_vector4() {
        let _log = crate::tests::test_init_log();
        // https://tools.ietf.org/html/rfc5769#section-2.4
        let data = vec![
            0x00, 0x01, 0x00, 0x60, //    Request type and message length
            0x21, 0x12, 0xa4, 0x42, //    Magic cookie
            0x78, 0xad, 0x34, 0x33, // }
            0xc6, 0xad, 0x72, 0xc0, // }  Transaction ID
            0x29, 0xda, 0x41, 0x2e, // }
            0x00, 0x06, 0x00, 0x12, //    USERNAME attribute header
            0xe3, 0x83, 0x9e, 0xe3, // }
            0x83, 0x88, 0xe3, 0x83, // }
            0xaa, 0xe3, 0x83, 0x83, // }  Username value (18 bytes) and padding (2 bytes)
            0xe3, 0x82, 0xaf, 0xe3, // }
            0x82, 0xb9, 0x00, 0x00, // }
            0x00, 0x15, 0x00, 0x1c, //    NONCE attribute header
            0x66, 0x2f, 0x2f, 0x34, // }
            0x39, 0x39, 0x6b, 0x39, // }
            0x35, 0x34, 0x64, 0x36, // }
            0x4f, 0x4c, 0x33, 0x34, // }  Nonce value
            0x6f, 0x4c, 0x39, 0x46, // }
            0x53, 0x54, 0x76, 0x79, // }
            0x36, 0x34, 0x73, 0x41, // }
            0x00, 0x14, 0x00, 0x0b, //    REALM attribute header
            0x65, 0x78, 0x61, 0x6d, // }
            0x70, 0x6c, 0x65, 0x2e, // }  Realm value (11 bytes) and padding (1 byte)
            0x6f, 0x72, 0x67, 0x00, // }
            0x00, 0x08, 0x00, 0x14, //    MESSAGE-INTEGRITY attribute header
            0xf6, 0x70, 0x24, 0x65, // }
            0x6d, 0xd6, 0x4a, 0x3e, // }
            0x02, 0xb8, 0xe0, 0x71, // }  HMAC-SHA1 fingerprint
            0x2e, 0x85, 0xc9, 0xa2, // }
            0x8c, 0xa8, 0x96, 0x66, // }
        ];

        let msg = Message::from_bytes(&data).unwrap();
        assert!(msg.has_class(MessageClass::Request));
        assert!(msg.has_method(BINDING));
        assert_eq!(msg.transaction_id(), 0x78ad_3433_c6ad_72c0_29da_412e.into());
        let mut builder = Message::builder(
            MessageType::from_class_method(MessageClass::Request, BINDING),
            msg.transaction_id(),
            MessageWriteVec::new(),
        );

        let long_term = LongTermCredentials {
            username: "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}".to_owned(),
            password: "The\u{00AD}M\u{00AA}tr\u{2168}".to_owned(),
            realm: "example.org".to_owned(),
        };
        // USERNAME
        assert!(msg.has_attribute(Username::TYPE));
        let raw = msg.raw_attribute(Username::TYPE).unwrap();
        assert!(Username::try_from(&raw).is_ok());
        let username = Username::try_from(&raw).unwrap();
        assert_eq!(username.username(), &long_term.username);
        builder.add_attribute(&username).unwrap();

        // NONCE
        let expected_nonce = "f//499k954d6OL34oL9FSTvy64sA";
        assert!(msg.has_attribute(Nonce::TYPE));
        let raw = msg.raw_attribute(Nonce::TYPE).unwrap();
        assert!(Nonce::try_from(&raw).is_ok());
        let nonce = Nonce::try_from(&raw).unwrap();
        assert_eq!(nonce.nonce(), expected_nonce);
        builder.add_attribute(&nonce).unwrap();

        // REALM
        assert!(msg.has_attribute(Realm::TYPE));
        let raw = msg.raw_attribute(Realm::TYPE).unwrap();
        assert!(Realm::try_from(&raw).is_ok());
        let realm = Realm::try_from(&raw).unwrap();
        assert_eq!(realm.realm(), long_term.realm());
        builder.add_attribute(&realm).unwrap();

        // MESSAGE_INTEGRITY
        /* XXX: the password needs SASLPrep-ing to be useful here
        let credentials = MessageIntegrityCredentials::LongTerm(long_term);
        assert!(matches!(msg.validate_integrity(&data, &credentials), Ok(())));
        */
        //builder.add_attribute(msg.raw_attribute(MessageIntegrity::TYPE).unwrap()).unwrap();

        assert_eq!(builder.finish()[4..], data[4..92]);
    }

    #[test]
    fn rfc8489_vector1() {
        let _log = crate::tests::test_init_log();
        // https://www.rfc-editor.org/rfc/rfc8489#appendix-B.1
        // https://www.rfc-editor.org/errata/eid6268
        let data = vec![
            0x00, 0x01, 0x00, 0x90, //     Request type and message length
            0x21, 0x12, 0xa4, 0x42, //     Magic cookie
            0x78, 0xad, 0x34, 0x33, //  }
            0xc6, 0xad, 0x72, 0xc0, //  }  Transaction ID
            0x29, 0xda, 0x41, 0x2e, //  }
            0x00, 0x1e, 0x00, 0x20, //     USERHASH attribute header
            0x4a, 0x3c, 0xf3, 0x8f, //  }
            0xef, 0x69, 0x92, 0xbd, //  }
            0xa9, 0x52, 0xc6, 0x78, //  }
            0x04, 0x17, 0xda, 0x0f, //  }  Userhash value (32 bytes)
            0x24, 0x81, 0x94, 0x15, //  }
            0x56, 0x9e, 0x60, 0xb2, //  }
            0x05, 0xc4, 0x6e, 0x41, //  }
            0x40, 0x7f, 0x17, 0x04, //  }
            0x00, 0x15, 0x00, 0x29, //     NONCE attribute header
            0x6f, 0x62, 0x4d, 0x61, //  }
            0x74, 0x4a, 0x6f, 0x73, //  }
            0x32, 0x41, 0x41, 0x41, //  }
            0x43, 0x66, 0x2f, 0x2f, //  }
            0x34, 0x39, 0x39, 0x6b, //  }  Nonce value and padding (3 bytes)
            0x39, 0x35, 0x34, 0x64, //  }
            0x36, 0x4f, 0x4c, 0x33, //  }
            0x34, 0x6f, 0x4c, 0x39, //  }
            0x46, 0x53, 0x54, 0x76, //  }
            0x79, 0x36, 0x34, 0x73, //  }
            0x41, 0x00, 0x00, 0x00, //  }
            0x00, 0x14, 0x00, 0x0b, //     REALM attribute header
            0x65, 0x78, 0x61, 0x6d, //  }
            0x70, 0x6c, 0x65, 0x2e, //  }  Realm value (11 bytes) and padding (1 byte)
            0x6f, 0x72, 0x67, 0x00, //  }
            0x00, 0x1d, 0x00, 0x04, //    PASSWORD-ALGORITHM attribute header
            0x00, 0x02, 0x00, 0x00, //    PASSWORD-ALGORITHM value (4 bytes)
            0x00, 0x1c, 0x00, 0x20, //    MESSAGE-INTEGRITY-SHA256 attribute header
            0xb5, 0xc7, 0xbf, 0x00, // }
            0x5b, 0x6c, 0x52, 0xa2, // }
            0x1c, 0x51, 0xc5, 0xe8, // }
            0x92, 0xf8, 0x19, 0x24, // }  HMAC-SHA256 value
            0x13, 0x62, 0x96, 0xcb, // }
            0x92, 0x7c, 0x43, 0x14, // }
            0x93, 0x09, 0x27, 0x8c, // }
            0xc6, 0x51, 0x8e, 0x65, // }
        ];

        let msg = Message::from_bytes(&data).unwrap();
        assert!(msg.has_class(MessageClass::Request));
        assert!(msg.has_method(BINDING));
        assert_eq!(msg.transaction_id(), 0x78ad_3433_c6ad_72c0_29da_412e.into());
        let mut builder = Message::builder(
            MessageType::from_class_method(MessageClass::Success, BINDING),
            msg.transaction_id(),
            MessageWriteVec::new(),
        );

        let long_term = LongTermCredentials {
            username: "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}".to_owned(),
            password: "The\u{00AD}M\u{00AA}tr\u{2168}".to_owned(),
            realm: "example.org".to_owned(),
        };
        // USERHASH
        assert!(msg.has_attribute(Userhash::TYPE));
        let raw = msg.raw_attribute(Userhash::TYPE).unwrap();
        assert!(Userhash::try_from(&raw).is_ok());
        let userhash = Userhash::try_from(&raw).unwrap();
        builder.add_attribute(&userhash).unwrap();

        // NONCE
        let expected_nonce = "obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA";
        assert!(msg.has_attribute(Nonce::TYPE));
        let raw = msg.raw_attribute(Nonce::TYPE).unwrap();
        assert!(Nonce::try_from(&raw).is_ok());
        let nonce = Nonce::try_from(&raw).unwrap();
        assert_eq!(nonce.nonce(), expected_nonce);
        builder.add_attribute(&nonce).unwrap();

        // REALM
        assert!(msg.has_attribute(Realm::TYPE));
        let raw = msg.raw_attribute(Realm::TYPE).unwrap();
        assert!(Realm::try_from(&raw).is_ok());
        let realm = Realm::try_from(&raw).unwrap();
        assert_eq!(realm.realm(), long_term.realm);
        builder.add_attribute(&realm).unwrap();

        // PASSWORD_ALGORITHM
        assert!(msg.has_attribute(PasswordAlgorithm::TYPE));
        let raw = msg.raw_attribute(PasswordAlgorithm::TYPE).unwrap();
        assert!(PasswordAlgorithm::try_from(&raw).is_ok());
        let algo = PasswordAlgorithm::try_from(&raw).unwrap();
        assert_eq!(algo.algorithm(), PasswordAlgorithmValue::SHA256);
        builder.add_attribute(&algo).unwrap();

        // MESSAGE_INTEGRITY_SHA256
        /* XXX: the password needs SASLPrep-ing to be useful here
        let credentials = MessageIntegrityCredentials::LongTerm(long_term);
        assert!(matches!(msg.validate_integrity(&data, &credentials), Ok(())));
        */
        //builder.add_attribute(msg.raw_attribute(MessageIntegritySha256::TYPE).unwrap()).unwrap();

        assert_eq!(builder.finish()[4..], data[4..128]);
    }
}
