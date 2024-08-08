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
//! use stun_types::message::{Message, BINDING};
//!
//! // Automatically generates a transaction ID.
//! let mut msg = Message::builder_request(BINDING);
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
//! let msg_data = msg.build();
//! // ignores the randomly generated transaction id
//! assert_eq!(msg_data[20..], attribute_data);
//! ```

use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder};

use crate::attribute::*;

use tracing::{debug, warn};

/// The value of the magic cookie (in network byte order) as specified in RFC5389, and RFC8489.
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// The value of the binding message type.  Can be used in either a request or an indication
/// message.
pub const BINDING: u16 = 0x0001;

#[derive(Debug, thiserror::Error)]
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
    #[error("Missing attribute {:?}", .0)]
    MissingAttribute(AttributeType),
    /// An attribute was found after the message integrity attribute
    #[error("An attribute {:?} was encountered after a message integrity attribute", .0)]
    AttributeAfterIntegrity(AttributeType),
    /// An attribute was found after the message integrity attribute
    #[error("An attribute {:?} was encountered after a fingerprint attribute", .0)]
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
    ShortTerm(ShortTermCredentials),
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
    Request,
    Indication,
    Success,
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
            "MessageType(class: {:?}, method: {} ({:#x}))",
            self.class(),
            self.method(),
            self.method()
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
    pub fn from_class_method(class: MessageClass, method: u16) -> Self {
        let class_bits = MessageClass::to_bits(class);
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
    pub fn method(self) -> u16 {
        self.0 & 0xf | (self.0 & 0xe0) >> 1 | (self.0 & 0x3e00) >> 2
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
    pub fn has_method(self, method: u16) -> bool {
        self.method() == method
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
        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();
        rng.gen::<u128>().into()
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
}

/// The structure that encapsulates the entirety of a STUN message
///
/// Contains the [`MessageType`], a transaction ID, and a list of STUN
/// [`Attribute`]
#[derive(Debug, Clone)]
pub struct Message<'a> {
    data: &'a [u8],
}

impl<'a> std::fmt::Display for Message<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Message(class: {:?}, method: {} ({:#x}), transaction: {}, attributes: ",
            self.get_type().class(),
            self.get_type().method(),
            self.get_type().method(),
            self.transaction_id()
        )?;
        let iter = self.iter_attributes();
        write!(f, "[")?;
        for (i, a) in iter.enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", a)?;
        }
        write!(f, "]")?;
        write!(f, ")")
    }
}

/// The supported hashing algorithms for ensuring integrity of a [`Message`]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityAlgorithm {
    Sha1,
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let mtype = MessageType::from_class_method(MessageClass::Indication, BINDING);
    /// let message = Message::builder(mtype, 0.into()).build();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert!(message.has_class(MessageClass::Indication));
    /// assert!(message.has_method(BINDING));
    /// ```
    pub fn builder<'b>(mtype: MessageType, transaction_id: TransactionId) -> MessageBuilder<'b> {
        MessageBuilder {
            msg_type: mtype,
            transaction_id,
            attributes: vec![],
        }
    }

    /// Create a new request [`Message`] of the provided method
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::builder_request(BINDING);
    /// let data = message.build();
    /// let message = Message::from_bytes(&data).unwrap();
    /// assert!(message.has_class(MessageClass::Request));
    /// assert!(message.has_method(BINDING));
    /// ```
    pub fn builder_request<'b>(method: u16) -> MessageBuilder<'b> {
        Message::builder(
            MessageType::from_class_method(MessageClass::Request, method),
            TransactionId::generate(),
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::builder_request(BINDING);
    /// let data = message.build();
    /// let message = Message::from_bytes(&data).unwrap();
    /// let success = Message::builder_success(&message).build();
    /// let success = Message::from_bytes(&success).unwrap();
    /// assert!(success.has_class(MessageClass::Success));
    /// assert!(success.has_method(BINDING));
    /// ```
    pub fn builder_success<'b>(orig: &Message) -> MessageBuilder<'b> {
        if !orig.has_class(MessageClass::Request) {
            panic!(
                "A success response message was attempted to be created from a non-request message"
            );
        }
        Message::builder(
            MessageType::from_class_method(MessageClass::Success, orig.method()),
            orig.transaction_id(),
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::builder_request(BINDING);
    /// let data = message.build();
    /// let message = Message::from_bytes(&data).unwrap();
    /// let error = Message::builder_error(&message).build();
    /// let error = Message::from_bytes(&error).unwrap();
    /// assert!(error.has_class(MessageClass::Error));
    /// assert!(error.has_method(BINDING));
    /// ```
    pub fn builder_error(orig: &Message) -> MessageBuilder<'a> {
        if !orig.has_class(MessageClass::Request) {
            panic!(
                "An error response message was attempted to be created from a non-request message"
            );
        }
        Message::builder(
            MessageType::from_class_method(MessageClass::Error, orig.method()),
            orig.transaction_id(),
        )
    }

    /// Retrieve the [`MessageType`] of a [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::builder_request(BINDING);
    /// let data = message.build();
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::builder_request(BINDING).build();
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::builder_request(BINDING).build();
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::builder_request(BINDING).build();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.is_response(), false);
    ///
    /// let error = Message::builder_error(&message).build();
    /// let error = Message::from_bytes(&error).unwrap();
    /// assert_eq!(error.is_response(), true);
    ///
    /// let success = Message::builder_success(&message).build();
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::builder_request(BINDING).build();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.method(), BINDING);
    /// ```
    pub fn method(&self) -> u16 {
        self.get_type().method()
    }

    /// Returns whether the [`Message`] is of the specified method
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let message = Message::builder_request(BINDING).build();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.has_method(BINDING), true);
    /// assert_eq!(message.has_method(0), false);
    /// ```
    pub fn has_method(&self, method: u16) -> bool {
        self.method() == method
    }

    /// Retrieves the 96-bit transaction ID of the [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING, TransactionId};
    /// let mtype = MessageType::from_class_method(MessageClass::Request, BINDING);
    /// let transaction_id = TransactionId::generate();
    /// let message = Message::builder(mtype, transaction_id).build();
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
                "malformed advertised size {:?} and data size {:?} don't match",
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
                warn!(
                    "failed to parse message attribute at offset {data_offset}: {:?}",
                    e
                );
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
            let padded_len = padded_attr_size(&attr);
            if padded_len > data.len() {
                warn!(
                    "attribute {:?} extends past the end of the data",
                    attr.get_type()
                );
                return Err(StunParseError::Truncated {
                    expected: data_offset + padded_len,
                    actual: data_offset + data.len(),
                });
            }
            if attr.get_type() == Fingerprint::TYPE {
                let f = Fingerprint::from_raw(&attr)?;
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING,
    ///     MessageIntegrityCredentials, LongTermCredentials, IntegrityAlgorithm};
    /// let mut message = Message::builder_request(BINDING);
    /// let credentials = LongTermCredentials::new(
    ///     "user".to_owned(),
    ///     "pass".to_owned(),
    ///     "realm".to_owned()
    /// ).into();
    /// assert!(message.add_message_integrity(&credentials, IntegrityAlgorithm::Sha256).is_ok());
    /// let data = message.build();
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
        debug!("using credentials {credentials:?}");
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
                    data_offset as u16 + attr.length() + 4 - MessageHeader::LENGTH as u16,
                );
                MessageIntegritySha256::verify(&hmac_data, &key, &msg_hmac)?;
                return Ok(algo);
            }
            let padded_len = padded_attr_size(&attr);
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let mut message = Message::builder_request(BINDING);
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// assert!(message.add_attribute(attr.clone()).is_ok());
    /// let message = message.build();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.raw_attribute(1.into()).unwrap(), attr);
    /// ```
    #[tracing::instrument(
        name = "message_get_raw_attribute",
        level = "trace",
        ret,
        skip(self, atype),
        fields(
            msg.transaction = %self.transaction_id(),
            attribute_type = %atype,
        )
    )]
    pub fn raw_attribute(&self, atype: AttributeType) -> Option<RawAttribute> {
        self.iter_attributes().find(|attr| attr.get_type() == atype)
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let mut message = Message::builder_request(BINDING);
    /// let attr = Software::new("stun-types").unwrap();
    /// assert!(message.add_attribute(&attr).is_ok());
    /// let message = message.build();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.attribute::<Software>().unwrap(), attr);
    /// ```
    #[tracing::instrument(
        name = "message_get_attribute",
        level = "trace",
        ret,
        skip(self),
        fields(
            msg.transaction = %self.transaction_id(),
            attribute_type = %A::TYPE,
        )
    )]
    pub fn attribute<A: AttributeFromRaw<StunParseError>>(&self) -> Result<A, StunParseError> {
        self.iter_attributes()
            .find(|attr| attr.get_type() == A::TYPE)
            .ok_or(StunParseError::MissingAttribute(A::TYPE))
            .and_then(|raw| A::from_raw(&raw))
    }

    /// Returns an iterator over the attributes in the [`Message`].
    pub fn iter_attributes(&self) -> impl Iterator<Item = RawAttribute> {
        MessageAttributesIter {
            data: self.data,
            data_i: MessageHeader::LENGTH,
            seen_message_integrity: false,
        }
    }

    /// Check that a message [`Message`] only contains required attributes that are supported and
    /// have at least some set of required attributes.  Returns an appropriate error message on
    /// failure to meet these requirements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// # use std::convert::TryInto;
    /// let mut builder = Message::builder_request(BINDING);
    /// let message = builder.build();
    /// let message = Message::from_bytes(&message).unwrap();
    /// // If nothing is required, no error response is returned
    /// assert!(matches!(Message::check_attribute_types(&message, &[], &[]), None));
    ///
    /// // If an atttribute is required that is not in the message, then an error response message
    /// // is generated
    /// let error_msg = Message::check_attribute_types(
    ///     &message,
    ///     &[],
    ///     &[Software::TYPE]
    /// ).unwrap();
    /// assert!(error_msg.has_attribute(ErrorCode::TYPE));
    /// let error_msg = error_msg.build();
    /// let error_msg = Message::from_bytes(&error_msg).unwrap();
    /// let error_code = error_msg.attribute::<ErrorCode>().unwrap();
    /// assert_eq!(error_code.code(), 400);
    ///
    /// let username = Username::new("user").unwrap();
    /// builder.add_attribute(&username).unwrap();
    /// let message = builder.build();
    /// let message = Message::from_bytes(&message).unwrap();
    /// // If a Username is in the message but is not advertised as supported then an
    /// // 'UNKNOWN-ATTRIBUTES' error response is returned
    /// let error_msg = Message::check_attribute_types(&message, &[], &[]).unwrap();
    /// let error_msg = error_msg.build();
    /// let error_msg = Message::from_bytes(&error_msg).unwrap();
    /// assert!(error_msg.is_response());
    /// assert!(error_msg.has_attribute(ErrorCode::TYPE));
    /// let error_code : ErrorCode = error_msg.attribute::<ErrorCode>().unwrap();
    /// assert_eq!(error_code.code(), 420);
    /// assert!(error_msg.has_attribute(UnknownAttributes::TYPE));
    /// ```
    #[tracing::instrument(
        level = "trace",
        skip(msg),
        fields(
            msg.transaction = %msg.transaction_id(),
        )
    )]
    pub fn check_attribute_types<'b>(
        msg: &Message,
        supported: &[AttributeType],
        required_in_msg: &[AttributeType],
    ) -> Option<MessageBuilder<'b>> {
        // Attribute -> AttributeType
        let unsupported: Vec<AttributeType> = msg
            .iter_attributes()
            .map(|a| a.get_type())
            // attribute types that require comprehension but are not supported by the caller
            .filter(|&at| at.comprehension_required() && !supported.iter().any(|&a| a == at))
            .collect();
        if !unsupported.is_empty() {
            warn!(
                "Message contains unknown comprehension required attributes {:?}, returning unknown attributes",
                unsupported
            );
            return Some(Message::unknown_attributes(msg, &unsupported));
        }
        let has_required_attribute_missing = required_in_msg
            .iter()
            // attribute types we need in the message -> failure -> Bad Request
            .any(|&at| !msg.iter_attributes().map(|a| a.get_type()).any(|a| a == at));
        if has_required_attribute_missing {
            warn!("Message is missing required attributes, returning bad request");
            return Some(Message::bad_request(msg));
        }
        None
    }

    /// Generate an error message with an [`ErrorCode`] attribute signalling 'Unknown Attribute'
    /// and an [`UnknownAttributes`] attribute containing the attributes that are unknown.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, BINDING};
    /// # use stun_types::attribute::*;
    /// # use std::convert::TryInto;
    /// let msg = Message::builder_request(BINDING).build();
    /// let msg = Message::from_bytes(&msg).unwrap();
    /// let error_msg = Message::unknown_attributes(&msg, &[Username::TYPE]).build();
    /// let error_msg = Message::from_bytes(&error_msg).unwrap();
    /// assert!(error_msg.is_response());
    /// assert!(error_msg.has_attribute(ErrorCode::TYPE));
    /// let error_code = error_msg.attribute::<ErrorCode>().unwrap();
    /// assert_eq!(error_code.code(), 420);
    /// let unknown = error_msg.attribute::<UnknownAttributes>().unwrap();
    /// assert!(unknown.has_attribute(Username::TYPE));
    /// ```
    pub fn unknown_attributes<'b>(
        src: &Message,
        attributes: &[AttributeType],
    ) -> MessageBuilder<'b> {
        let mut out = Message::builder_error(src);
        let software = Software::new("stun-types").unwrap();
        out.add_attribute(&software).unwrap();
        out.add_attribute(&ErrorCode::new(420, "Unknown Attributes").unwrap())
            .unwrap();
        if !attributes.is_empty() {
            out.add_attribute(&UnknownAttributes::new(attributes))
                .unwrap();
        }
        out.into_owned()
    }

    /// Generate an error message with an [`ErrorCode`] attribute signalling a 'Bad Request'
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// # use stun_types::attribute::*;
    /// # use std::convert::TryInto;
    /// let msg = Message::builder_request(BINDING).build();
    /// let msg = Message::from_bytes(&msg).unwrap();
    /// let error_msg = Message::bad_request(&msg).build();
    /// let error_msg = Message::from_bytes(&error_msg).unwrap();
    /// assert!(error_msg.has_attribute(ErrorCode::TYPE));
    /// let error_code =  error_msg.attribute::<ErrorCode>().unwrap();
    /// assert_eq!(error_code.code(), 400);
    /// ```
    pub fn bad_request<'b>(src: &Message) -> MessageBuilder<'b> {
        let mut out = Message::builder_error(src);
        let software = Software::new("stun-types").unwrap();
        out.add_attribute(&software).unwrap();
        out.add_attribute(&ErrorCode::new(400, "Bad Request").unwrap())
            .unwrap();
        out.into_owned()
    }

    /// Whether this message contains an attribute of the specified type.
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// # use stun_types::attribute::{Software, Attribute};
    /// let mut msg = Message::builder_request(BINDING);
    /// let attr = Software::new("stun-types").unwrap();
    /// assert!(msg.add_attribute(&attr).is_ok());
    /// let msg = msg.build();
    /// let msg = Message::from_bytes(&msg).unwrap();
    /// assert!(msg.has_attribute(Software::TYPE));
    /// ```
    pub fn has_attribute(&self, atype: AttributeType) -> bool {
        self.iter_attributes().any(|attr| attr.get_type() == atype)
    }
}
impl<'a> TryFrom<&'a [u8]> for Message<'a> {
    type Error = StunParseError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Message::from_bytes(value)
    }
}

#[doc(hidden)]
pub struct MessageAttributesIter<'a> {
    data: &'a [u8],
    data_i: usize,
    seen_message_integrity: bool,
}

impl<'a> Iterator for MessageAttributesIter<'a> {
    type Item = RawAttribute<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data_i >= self.data.len() {
            return None;
        }

        let Ok(attr) = RawAttribute::from_bytes(&self.data[self.data_i..]) else {
            self.data_i = self.data.len();
            return None;
        };
        let padded_len = padded_attr_size(&attr);
        self.data_i += padded_len;
        if self.seen_message_integrity {
            if attr.get_type() == Fingerprint::TYPE {
                return Some(attr);
            }
            return None;
        }
        if attr.get_type() == MessageIntegrity::TYPE
            || attr.get_type() == MessageIntegritySha256::TYPE
        {
            self.seen_message_integrity = true;
        }

        Some(attr)
    }
}

/// A builder of a STUN Message to a sequence of bytes.
#[derive(Clone, Debug)]
pub struct MessageBuilder<'a> {
    msg_type: MessageType,
    transaction_id: TransactionId,
    attributes: Vec<RawAttribute<'a>>,
}

impl<'a> MessageBuilder<'a> {
    /// Consume this builder and produce a new owned version.
    pub fn into_owned<'b>(self) -> MessageBuilder<'b> {
        MessageBuilder {
            msg_type: self.msg_type,
            transaction_id: self.transaction_id,
            attributes: self
                .attributes
                .into_iter()
                .map(|attr| attr.into_owned())
                .collect(),
        }
    }

    /// Retrieves the 96-bit transaction ID of the [`Message`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING, TransactionId};
    /// let mtype = MessageType::from_class_method(MessageClass::Request, BINDING);
    /// let transaction_id = TransactionId::generate();
    /// let message = Message::builder(mtype, transaction_id).build();
    /// let message = Message::from_bytes(&message).unwrap();
    /// assert_eq!(message.transaction_id(), transaction_id);
    /// ```
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Whether this [`MessageBuilder`] is for a particular [`MessageClass`]
    pub fn has_class(&self, cls: MessageClass) -> bool {
        self.msg_type.class() == cls
    }

    /// Serialize a `MessageBuilder` to network bytes
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::{RawAttribute, Attribute};
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let mut message = Message::builder(MessageType::from_class_method(MessageClass::Request, BINDING), 1000.into());
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// assert!(message.add_attribute(attr).is_ok());
    /// assert_eq!(message.build(), vec![0, 1, 0, 8, 33, 18, 164, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232, 0, 1, 0, 1, 3, 0, 0, 0]);
    /// ```
    #[tracing::instrument(
        name = "message_build",
        level = "trace",
        skip(self),
        fields(
            msg.transaction_id = %self.transaction_id()
        )
    )]
    pub fn build(&self) -> Vec<u8> {
        let mut attr_size = 0;
        for attr in &self.attributes {
            attr_size += padded_attr_size(attr);
        }
        let mut ret = Vec::with_capacity(MessageHeader::LENGTH + attr_size);
        ret.extend(self.msg_type.to_bytes());
        ret.resize(MessageHeader::LENGTH, 0);
        let transaction: u128 = self.transaction_id.into();
        let tid = (MAGIC_COOKIE as u128) << 96 | transaction & 0xffff_ffff_ffff_ffff_ffff_ffff;
        BigEndian::write_u128(&mut ret[4..20], tid);
        BigEndian::write_u16(&mut ret[2..4], attr_size as u16);
        for attr in &self.attributes {
            let bytes = attr.to_bytes();
            ret.extend(bytes);
        }
        ret
    }

    // message-integrity is computed using all the data up to (exclusive of) the
    // MESSAGE-INTEGRITY but with a length field including the MESSAGE-INTEGRITY attribute...
    fn integrity_bytes_from_message(&self, extra_len: u16) -> Vec<u8> {
        let mut bytes = self.build();
        // rewrite the length to include the message-integrity attribute
        let existing_len = BigEndian::read_u16(&bytes[2..4]);
        BigEndian::write_u16(&mut bytes[2..4], existing_len + extra_len);
        bytes
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING,
    ///     MessageIntegrityCredentials, ShortTermCredentials, IntegrityAlgorithm, StunWriteError};
    /// # use stun_types::attribute::{Attribute, MessageIntegrity, MessageIntegritySha256};
    /// let mut message = Message::builder_request(BINDING);
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
    /// let data = message.build();
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
    pub fn add_message_integrity(
        &mut self,
        credentials: &MessageIntegrityCredentials,
        algorithm: IntegrityAlgorithm,
    ) -> Result<(), StunWriteError> {
        if self.has_attribute(MessageIntegrity::TYPE) && algorithm == IntegrityAlgorithm::Sha1 {
            return Err(StunWriteError::AttributeExists(MessageIntegrity::TYPE));
        }
        if self.has_attribute(MessageIntegritySha256::TYPE) {
            return Err(StunWriteError::AttributeExists(
                MessageIntegritySha256::TYPE,
            ));
        }
        if self.has_attribute(Fingerprint::TYPE) {
            return Err(StunWriteError::FingerprintExists);
        }

        self.add_message_integrity_unchecked(credentials, algorithm);

        Ok(())
    }

    fn add_message_integrity_unchecked(
        &mut self,
        credentials: &MessageIntegrityCredentials,
        algorithm: IntegrityAlgorithm,
    ) {
        let key = credentials.make_hmac_key();
        match algorithm {
            IntegrityAlgorithm::Sha1 => {
                let bytes = self.integrity_bytes_from_message(24);
                let integrity = MessageIntegrity::compute(&bytes, &key).unwrap();
                self.attributes
                    .push(RawAttribute::from(&MessageIntegrity::new(integrity)).into_owned());
            }
            IntegrityAlgorithm::Sha256 => {
                let bytes = self.integrity_bytes_from_message(36);
                let integrity = MessageIntegritySha256::compute(&bytes, &key).unwrap();
                self.attributes.push(
                    RawAttribute::from(&MessageIntegritySha256::new(integrity.as_slice()).unwrap())
                        .into_owned(),
                );
            }
        }
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let mut message = Message::builder_request(BINDING);
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
    pub fn add_fingerprint(&mut self) -> Result<(), StunWriteError> {
        if self.has_attribute(Fingerprint::TYPE) {
            return Err(StunWriteError::AttributeExists(Fingerprint::TYPE));
        }

        self.add_fingerprint_unchecked();

        Ok(())
    }

    fn add_fingerprint_unchecked(&mut self) {
        // fingerprint is computed using all the data up to (exclusive of) the FINGERPRINT
        // but with a length field including the FINGERPRINT attribute...
        let mut bytes = self.build();
        // rewrite the length to include the fingerprint attribute
        let existing_len = BigEndian::read_u16(&bytes[2..4]);
        BigEndian::write_u16(&mut bytes[2..4], existing_len + 8);
        let fingerprint = Fingerprint::compute(&bytes);
        self.attributes
            .push(RawAttribute::from(&Fingerprint::new(fingerprint)));
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
    /// # use stun_types::message::{Message, MessageType, MessageClass, BINDING};
    /// let mut message = Message::builder_request(BINDING);
    /// let attr = RawAttribute::new(1.into(), &[3]);
    /// assert!(message.add_attribute(attr.clone()).is_ok());
    /// assert!(message.add_attribute(attr).is_err());
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
    pub fn add_attribute(
        &mut self,
        attr: impl Into<RawAttribute<'a>>,
    ) -> Result<(), StunWriteError> {
        let raw = attr.into();
        //trace!("adding attribute {:?}", attr);
        if raw.get_type() == MessageIntegrity::TYPE {
            panic!("Cannot write MessageIntegrity with `add_attribute`.  Use add_message_integrity() instead");
        }
        if raw.get_type() == MessageIntegritySha256::TYPE {
            panic!("Cannot write MessageIntegritySha256 with `add_attribute`.  Use add_message_integrity() instead");
        }
        if raw.get_type() == Fingerprint::TYPE {
            panic!("Cannot write Fingerprint with `add_attribute`.  Use add_fingerprint() instead");
        }
        if self.has_attribute(raw.get_type()) {
            return Err(StunWriteError::AttributeExists(raw.get_type()));
        }
        // can't validly add generic attributes after message integrity or fingerprint
        if self.has_attribute(MessageIntegrity::TYPE) {
            return Err(StunWriteError::MessageIntegrityExists);
        }
        if self.has_attribute(MessageIntegritySha256::TYPE) {
            return Err(StunWriteError::MessageIntegrityExists);
        }
        if self.has_attribute(Fingerprint::TYPE) {
            return Err(StunWriteError::FingerprintExists);
        }
        self.attributes.push(raw);
        Ok(())
    }

    /// Return whether this [`MessageBuilder`] contains a particular attribute.
    pub fn has_attribute(&self, atype: AttributeType) -> bool {
        self.attributes.iter().any(|attr| attr.get_type() == atype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_type_roundtrip() {
        let _log = crate::tests::test_init_log();
        /* validate that all methods/classes survive a roundtrip */
        for m in 0..0xfff {
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
            }
        }
    }

    #[test]
    fn msg_roundtrip() {
        let _log = crate::tests::test_init_log();
        /* validate that all methods/classes survive a roundtrip */
        for m in (0x009..0x4ff).step_by(0x123) {
            let classes = vec![
                MessageClass::Request,
                MessageClass::Indication,
                MessageClass::Success,
                MessageClass::Error,
            ];
            for c in classes {
                let mtype = MessageType::from_class_method(c, m);
                for tid in (0x18..0xff_ffff_ffff_ffff_ffff).step_by(0xfedc_ba98_7654_3210) {
                    let mut msg = Message::builder(mtype, tid.into());
                    let attr = RawAttribute::new(1.into(), &[3]);
                    assert!(msg.add_attribute(attr.clone()).is_ok());
                    let data = msg.build();

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
        let src = Message::builder_request(BINDING).build();
        let src = Message::from_bytes(&src).unwrap();
        let msg = Message::unknown_attributes(&src, &[Software::TYPE]).build();
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
        let src = Message::builder_request(BINDING).build();
        let src = Message::from_bytes(&src).unwrap();
        let msg = Message::bad_request(&src).build();
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
        let mut msg = Message::builder_request(BINDING);
        let software = Software::new("s").unwrap();
        msg.add_attribute(&software).unwrap();
        msg.add_fingerprint().unwrap();
        let bytes = msg.build();
        // validates the fingerprint of the data when available
        let new_msg = Message::from_bytes(&bytes).unwrap();
        let software = new_msg.attribute::<Software>().unwrap();
        assert_eq!(software.software(), "s");
        let _new_fingerprint = new_msg.attribute::<Fingerprint>().unwrap();
    }

    #[test]
    fn integrity() {
        let _log = crate::tests::test_init_log();
        for algorithm in [IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256] {
            let credentials = ShortTermCredentials::new("secret".to_owned()).into();
            let mut msg = Message::builder_request(BINDING);
            let software = Software::new("s").unwrap();
            msg.add_attribute(&software).unwrap();
            msg.add_message_integrity(&credentials, algorithm).unwrap();
            let bytes = msg.build();
            // validates the fingerprint of the data when available
            let new_msg = Message::from_bytes(&bytes).unwrap();
            new_msg.validate_integrity(&credentials).unwrap();
            let software = new_msg.attribute::<Software>().unwrap();
            assert_eq!(software.software(), "s");
        }
    }

    #[test]
    fn add_duplicate_integrity() {
        let _log = crate::tests::test_init_log();
        let credentials = ShortTermCredentials::new("secret".to_owned()).into();
        let mut msg = Message::builder_request(BINDING);
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
        let mut msg = Message::builder_request(BINDING);
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
            let mut msg = Message::builder_request(BINDING);
            msg.add_message_integrity(&credentials, algorithm).unwrap();
            let software = Software::new("s").unwrap();
            assert!(matches!(
                msg.add_attribute(&software),
                Err(StunWriteError::MessageIntegrityExists)
            ));
        }
    }

    #[test]
    fn add_integrity_after_fingerprint() {
        let _log = crate::tests::test_init_log();
        for algorithm in [IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256] {
            let credentials = ShortTermCredentials::new("secret".to_owned()).into();
            let mut msg = Message::builder_request(BINDING);
            msg.add_fingerprint().unwrap();
            assert!(matches!(
                msg.add_message_integrity(&credentials, algorithm),
                Err(StunWriteError::FingerprintExists)
            ));
        }
    }

    #[test]
    fn duplicate_fingerprint() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING);
        msg.add_fingerprint().unwrap();
        assert!(matches!(
            msg.add_fingerprint(),
            Err(StunWriteError::AttributeExists(Fingerprint::TYPE))
        ));
    }

    #[test]
    fn parse_invalid_fingerprint() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING);
        msg.add_fingerprint().unwrap();
        let mut bytes = msg.build();
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
        let mut msg = Message::builder_request(BINDING);
        msg.add_fingerprint().unwrap();
        let mut bytes = msg.build();
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
            let mut msg = Message::builder_request(BINDING);
            msg.add_message_integrity(&credentials, algorithm).unwrap();
            let mut bytes = msg.build();
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
            let mut msg = Message::builder_request(BINDING);
            msg.add_message_integrity(&credentials, algorithm).unwrap();
            // duplicate integrity attribute. Don't do this in real code!
            msg.add_message_integrity_unchecked(&credentials, algorithm);
            let bytes = msg.build();
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
        let mut msg = Message::builder_request(BINDING);
        msg.add_fingerprint().unwrap();
        let mut bytes = msg.build();
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
        let mut msg = Message::builder_request(BINDING);
        msg.add_fingerprint().unwrap();
        msg.add_fingerprint_unchecked();
        let bytes = msg.build();
        assert!(matches!(
            Message::from_bytes(&bytes),
            Err(StunParseError::AttributeAfterFingerprint(Fingerprint::TYPE))
        ));
    }

    #[test]
    fn add_attribute_after_fingerprint() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING);
        msg.add_fingerprint().unwrap();
        let software = Software::new("s").unwrap();
        assert!(matches!(
            msg.add_attribute(&software),
            Err(StunWriteError::FingerprintExists)
        ));
    }

    #[test]
    fn parse_truncated_message_header() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING);
        msg.add_fingerprint().unwrap();
        let bytes = msg.build();
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
        let mut msg = Message::builder_request(BINDING);
        msg.add_fingerprint().unwrap();
        let bytes = msg.build();
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
        let mut msg = Message::builder_request(BINDING);
        msg.add_fingerprint().unwrap();
        let mut bytes = msg.build();
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
        let mut src = Message::builder_request(BINDING);
        let username = Username::new("123").unwrap();
        src.add_attribute(&username).unwrap();
        src.add_attribute(&Priority::new(123)).unwrap();
        let src = src.build();
        let src = Message::from_bytes(&src).unwrap();

        // success case
        let res = Message::check_attribute_types(
            &src,
            &[Username::TYPE, Priority::TYPE],
            &[Username::TYPE],
        );
        assert!(res.is_none());

        // fingerprint required but not present
        let res = Message::check_attribute_types(
            &src,
            &[Username::TYPE, Priority::TYPE],
            &[Fingerprint::TYPE],
        );
        assert!(res.is_some());
        let res = res.unwrap();
        let res = res.build();
        let res = Message::from_bytes(&res).unwrap();
        assert!(res.has_class(MessageClass::Error));
        assert!(res.has_method(src.method()));
        let err = res.attribute::<ErrorCode>().unwrap();
        assert_eq!(err.code(), 400);

        // priority unsupported
        let res = Message::check_attribute_types(&src, &[Username::TYPE], &[]);
        assert!(res.is_some());
        let res = res.unwrap();
        let data = res.build();
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
        )
        .build();
        let msg = Message::from_bytes(&msg).unwrap();
        let _builder = Message::builder_success(&msg);
    }

    #[test]
    #[should_panic(expected = "created from a non-request message")]
    fn builder_error_panic() {
        let _log = crate::tests::test_init_log();
        let msg = Message::builder(
            MessageType::from_class_method(MessageClass::Indication, BINDING),
            TransactionId::generate(),
        )
        .build();
        let msg = Message::from_bytes(&msg).unwrap();
        let _builder = Message::builder_error(&msg);
    }

    #[test]
    #[should_panic(expected = "Use add_message_integrity() instead")]
    fn builder_add_attribute_integrity_panic() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING);
        let hmac = [2; 20];
        let integrity = MessageIntegrity::new(hmac);
        msg.add_attribute(&integrity).unwrap();
    }

    #[test]
    #[should_panic(expected = "Use add_message_integrity() instead")]
    fn builder_add_attribute_integrity_sha256_panic() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING);
        let hmac = [2; 16];
        let integrity = MessageIntegritySha256::new(&hmac).unwrap();
        msg.add_attribute(&integrity).unwrap();
    }

    #[test]
    #[should_panic(expected = "Use add_fingerprint() instead")]
    fn builder_add_attribute_fingerprint_panic() {
        let _log = crate::tests::test_init_log();
        let mut msg = Message::builder_request(BINDING);
        let fingerprint = [2; 4];
        let integrity = Fingerprint::new(fingerprint);
        msg.add_attribute(&integrity).unwrap();
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
        );

        // SOFTWARE
        assert!(msg.has_attribute(Software::TYPE));
        let raw = msg.raw_attribute(Software::TYPE).unwrap();
        assert!(matches!(Software::try_from(&raw), Ok(_)));
        let software = Software::try_from(&raw).unwrap();
        assert_eq!(software.software(), "STUN test client");
        builder.add_attribute(&software).unwrap();

        // PRIORITY
        assert!(msg.has_attribute(Priority::TYPE));
        let raw = msg.raw_attribute(Priority::TYPE).unwrap();
        assert!(matches!(Priority::try_from(&raw), Ok(_)));
        let priority = Priority::try_from(&raw).unwrap();
        assert_eq!(priority.priority(), 0x6e0001ff);
        builder.add_attribute(&priority).unwrap();

        // ICE-CONTROLLED
        assert!(msg.has_attribute(IceControlled::TYPE));
        let raw = msg.raw_attribute(IceControlled::TYPE).unwrap();
        assert!(matches!(IceControlled::try_from(&raw), Ok(_)));
        let ice = IceControlled::try_from(&raw).unwrap();
        assert_eq!(ice.tie_breaker(), 0x932f_f9b1_5126_3b36);
        builder.add_attribute(&ice).unwrap();

        // USERNAME
        assert!(msg.has_attribute(Username::TYPE));
        let raw = msg.raw_attribute(Username::TYPE).unwrap();
        assert!(matches!(Username::try_from(&raw), Ok(_)));
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
        let mut msg_data = builder.build();
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
        );

        // SOFTWARE
        assert!(msg.has_attribute(Software::TYPE));
        let raw = msg.raw_attribute(Software::TYPE).unwrap();
        assert!(matches!(Software::try_from(&raw), Ok(_)));
        let software = Software::try_from(&raw).unwrap();
        assert_eq!(software.software(), "test vector");
        builder.add_attribute(&software).unwrap();

        // XOR_MAPPED_ADDRESS
        assert!(msg.has_attribute(XorMappedAddress::TYPE));
        let raw = msg.raw_attribute(XorMappedAddress::TYPE).unwrap();
        assert!(matches!(XorMappedAddress::try_from(&raw), Ok(_)));
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
        debug!("{:?}", ret);
        assert!(matches!(ret, Ok(IntegrityAlgorithm::Sha1)));
        builder
            .add_message_integrity(&credentials, IntegrityAlgorithm::Sha1)
            .unwrap();

        // FINGERPRINT is checked by Message::from_bytes() when present
        assert!(msg.has_attribute(Fingerprint::TYPE));
        builder.add_fingerprint().unwrap();

        // assert that we produce the same output as we parsed in this case
        let mut msg_data = builder.build();
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
        );

        // SOFTWARE
        assert!(msg.has_attribute(Software::TYPE));
        let raw = msg.raw_attribute(Software::TYPE).unwrap();
        assert!(matches!(Software::try_from(&raw), Ok(_)));
        let software = Software::try_from(&raw).unwrap();
        assert_eq!(software.software(), "test vector");
        builder.add_attribute(&software).unwrap();

        // XOR_MAPPED_ADDRESS
        assert!(msg.has_attribute(XorMappedAddress::TYPE));
        let raw = msg.raw_attribute(XorMappedAddress::TYPE).unwrap();
        assert!(matches!(XorMappedAddress::try_from(&raw), Ok(_)));
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
        let mut msg_data = builder.build();
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
        );

        let long_term = LongTermCredentials {
            username: "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}".to_owned(),
            password: "The\u{00AD}M\u{00AA}tr\u{2168}".to_owned(),
            realm: "example.org".to_owned(),
        };
        // USERNAME
        assert!(msg.has_attribute(Username::TYPE));
        let raw = msg.raw_attribute(Username::TYPE).unwrap();
        assert!(matches!(Username::try_from(&raw), Ok(_)));
        let username = Username::try_from(&raw).unwrap();
        assert_eq!(username.username(), &long_term.username);
        builder.add_attribute(&username).unwrap();

        // NONCE
        let expected_nonce = "f//499k954d6OL34oL9FSTvy64sA";
        assert!(msg.has_attribute(Nonce::TYPE));
        let raw = msg.raw_attribute(Nonce::TYPE).unwrap();
        assert!(matches!(Nonce::try_from(&raw), Ok(_)));
        let nonce = Nonce::try_from(&raw).unwrap();
        assert_eq!(nonce.nonce(), expected_nonce);
        builder.add_attribute(&nonce).unwrap();

        // REALM
        assert!(msg.has_attribute(Realm::TYPE));
        let raw = msg.raw_attribute(Realm::TYPE).unwrap();
        assert!(matches!(Realm::try_from(&raw), Ok(_)));
        let realm = Realm::try_from(&raw).unwrap();
        assert_eq!(realm.realm(), long_term.realm());
        builder.add_attribute(&realm).unwrap();

        // MESSAGE_INTEGRITY
        /* XXX: the password needs SASLPrep-ing to be useful here
        let credentials = MessageIntegrityCredentials::LongTerm(long_term);
        assert!(matches!(msg.validate_integrity(&data, &credentials), Ok(())));
        */
        //builder.add_attribute(msg.raw_attribute(MessageIntegrity::TYPE).unwrap()).unwrap();

        assert_eq!(builder.build()[4..], data[4..92]);
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
        );

        let long_term = LongTermCredentials {
            username: "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}".to_owned(),
            password: "The\u{00AD}M\u{00AA}tr\u{2168}".to_owned(),
            realm: "example.org".to_owned(),
        };
        // USERHASH
        assert!(msg.has_attribute(Userhash::TYPE));
        let raw = msg.raw_attribute(Userhash::TYPE).unwrap();
        assert!(matches!(Userhash::try_from(&raw), Ok(_)));
        let userhash = Userhash::try_from(&raw).unwrap();
        builder.add_attribute(&userhash).unwrap();

        // NONCE
        let expected_nonce = "obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA";
        assert!(msg.has_attribute(Nonce::TYPE));
        let raw = msg.raw_attribute(Nonce::TYPE).unwrap();
        assert!(matches!(Nonce::try_from(&raw), Ok(_)));
        let nonce = Nonce::try_from(&raw).unwrap();
        assert_eq!(nonce.nonce(), expected_nonce);
        builder.add_attribute(&nonce).unwrap();

        // REALM
        assert!(msg.has_attribute(Realm::TYPE));
        let raw = msg.raw_attribute(Realm::TYPE).unwrap();
        assert!(matches!(Realm::try_from(&raw), Ok(_)));
        let realm = Realm::try_from(&raw).unwrap();
        assert_eq!(realm.realm(), long_term.realm);
        builder.add_attribute(&realm).unwrap();

        // PASSWORD_ALGORITHM
        assert!(msg.has_attribute(PasswordAlgorithm::TYPE));
        let raw = msg.raw_attribute(PasswordAlgorithm::TYPE).unwrap();
        assert!(matches!(PasswordAlgorithm::try_from(&raw), Ok(_)));
        let algo = PasswordAlgorithm::try_from(&raw).unwrap();
        assert_eq!(algo.algorithm(), PasswordAlgorithmValue::SHA256);
        builder.add_attribute(&algo).unwrap();

        // MESSAGE_INTEGRITY_SHA256
        /* XXX: the password needs SASLPrep-ing to be useful here
        let credentials = MessageIntegrityCredentials::LongTerm(long_term);
        assert!(matches!(msg.validate_integrity(&data, &credentials), Ok(())));
        */
        //builder.add_attribute(msg.raw_attribute(MessageIntegritySha256::TYPE).unwrap()).unwrap();

        assert_eq!(builder.build()[4..], data[4..128]);
    }
}
