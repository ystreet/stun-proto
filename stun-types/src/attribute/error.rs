// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder};

use crate::message::{StunParseError, StunWriteError};

use super::{
    Attribute, AttributeExt, AttributeStaticType, AttributeType, AttributeWrite, AttributeWriteExt,
    RawAttribute,
};

/// The ErrorCode [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorCode {
    code: u16,
    reason: String,
}
impl AttributeStaticType for ErrorCode {
    const TYPE: AttributeType = AttributeType(0x0009);
}
impl Attribute for ErrorCode {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        self.reason.len() as u16 + 4
    }
}

impl AttributeWrite for ErrorCode {
    fn to_raw(&self) -> RawAttribute {
        let mut data = Vec::with_capacity(self.length() as usize);
        data.push(0u8);
        data.push(0u8);
        data.push((self.code / 100) as u8);
        data.push((self.code % 100) as u8);
        data.extend(self.reason.as_bytes());
        RawAttribute::new_owned(ErrorCode::TYPE, data.into_boxed_slice())
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        let len = self.padded_len();
        let mut offset = self.write_header_unchecked(dest);
        offset += self.write_into_data(&mut dest[offset..]);
        if len - offset > 0 {
            dest[offset..len].fill(0);
        }
    }
}
impl<'a> TryFrom<&RawAttribute<'a>> for ErrorCode {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..=763 + 4)?;
        let code_h = (raw.value[2] & 0x7) as u16;
        let code_tens = raw.value[3] as u16;
        if !(3..7).contains(&code_h) || code_tens > 99 {
            return Err(StunParseError::InvalidAttributeData);
        }
        let code = code_h * 100 + code_tens;
        Ok(Self {
            code,
            reason: std::str::from_utf8(&raw.value[4..])
                .map_err(|_| StunParseError::InvalidAttributeData)?
                .to_owned(),
        })
    }
}

/// Builder for an [`ErrorCode`]
#[derive(Debug)]
pub struct ErrorCodeBuilder<'reason> {
    code: u16,
    reason: Option<&'reason str>,
}

impl<'reason> ErrorCodeBuilder<'reason> {
    fn new(code: u16) -> Self {
        Self { code, reason: None }
    }

    /// Set the custom reason for this [`ErrorCode`]
    pub fn reason(mut self, reason: &'reason str) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Create the [`ErrorCode`] with the configured paramaters
    ///
    /// # Errors
    ///
    /// - When the code value is out of range [300, 699]
    pub fn build(self) -> Result<ErrorCode, StunWriteError> {
        if !(300..700).contains(&self.code) {
            return Err(StunWriteError::OutOfRange {
                value: self.code as usize,
                min: 300,
                max: 699,
            });
        }
        let reason = self
            .reason
            .unwrap_or_else(|| ErrorCode::default_reason_for_code(self.code))
            .to_owned();
        Ok(ErrorCode {
            code: self.code,
            reason,
        })
    }
}

impl ErrorCode {
    /// Try an alternate server.  The
    /// [`AlternateServer`](crate::attribute::alternate::AlternateServer) or
    /// [`AlternateDomain`](crate::attribute::alternate::AlternateDomain) contains the location of
    /// where to forward this request.
    pub const TRY_ALTERNATE: u16 = 301;
    /// The request was malformed and could not be processed.
    pub const BAD_REQUEST: u16 = 400;
    /// The required credentials were not found or did not match.
    pub const UNAUTHORIZED: u16 = 401;
    /// Not allowed to access this resource.
    pub const FORBIDDEN: u16 = 403;
    /// An unknown comprehension required attribute was present.  The [`UnknownAttributes`]
    /// contains the specific attribute/s.
    pub const UNKNOWN_ATTRIBUTE: u16 = 420;
    /// The allocation already exists on this server.
    pub const ALLOCATION_MISMATCH: u16 = 437;
    /// The nonce is no longer valid.
    pub const STALE_NONCE: u16 = 438;
    /// The address family (IPv4, IPv6) is not supported.
    pub const ADDRESS_FAMILY_NOT_SUPPORTED: u16 = 440;
    /// Incorrect credentials provided.
    pub const WRONG_CREDENTIALS: u16 = 441;
    /// The transport protocol (UDP, TCP) is not supported.
    pub const UNSUPPORTED_TRANSPORT_PROTOCOL: u16 = 442;
    /// The peer address family does not match the TURN allocation.
    pub const PEER_ADDRESS_FAMILY_MISMATCH: u16 = 443;
    /// This username has reached its limit of allocations currently allowed.
    pub const ALLOCATION_QUOTA_REACHED: u16 = 486;
    /// Requestor must switch ICE roles.
    pub const ROLE_CONFLICT: u16 = 487;
    /// An unspecificed error has occurred.
    pub const SERVER_ERROR: u16 = 500;
    /// The server does not have capacity to handle this request.
    pub const INSUFFICIENT_CAPACITY: u16 = 508;

    /// Create a builder for creating a new [`ErrorCode`] [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let error = ErrorCode::builder (400).reason("bad error").build().unwrap();
    /// assert_eq!(error.code(), 400);
    /// assert_eq!(error.reason(), "bad error");
    /// ```
    pub fn builder<'reason>(code: u16) -> ErrorCodeBuilder<'reason> {
        ErrorCodeBuilder::new(code)
    }

    /// Create a new [`ErrorCode`] [`Attribute`]
    ///
    /// # Errors
    ///
    /// - When the code value is out of range [300, 699]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let error = ErrorCode::new (400, "bad error").unwrap();
    /// assert_eq!(error.code(), 400);
    /// assert_eq!(error.reason(), "bad error");
    /// ```
    pub fn new(code: u16, reason: &str) -> Result<Self, StunWriteError> {
        if !(300..700).contains(&code) {
            return Err(StunWriteError::OutOfRange {
                value: code as usize,
                min: 300,
                max: 699,
            });
        }
        Ok(Self {
            code,
            reason: reason.to_owned(),
        })
    }

    /// The error code value
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let error = ErrorCode::new (400, "bad error").unwrap();
    /// assert_eq!(error.code(), 400);
    /// ```
    pub fn code(&self) -> u16 {
        self.code
    }

    /// The error code reason string
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let error = ErrorCode::new (400, "bad error").unwrap();
    /// assert_eq!(error.reason(), "bad error");
    /// ```
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Return some default reason strings for some error code values
    ///
    /// Currently the following are supported.
    ///
    ///  - 301 -> Try Alternate
    ///  - 400 -> Bad Request
    ///  - 401 -> Unauthorized
    ///  - 403 -> Forbidden
    ///  - 420 -> Unknown Attribute
    ///  - 437 -> Allocation Mismatch
    ///  - 438 -> Stale Nonce
    ///  - 440 -> Address Family Not Supported
    ///  - 441 -> Wrong Credentials
    ///  - 442 -> Supported Transport Protocol
    ///  - 443 -> Peer Address Family Mismatch
    ///  - 486 -> Allocation Quota Reached
    ///  - 487 -> Role Conflict
    ///  - 500 -> Server Error
    ///  - 508 -> Insufficient Capacity
    pub fn default_reason_for_code(code: u16) -> &'static str {
        match code {
            Self::TRY_ALTERNATE => "Try Alternate",
            Self::BAD_REQUEST => "Bad Request",
            Self::UNAUTHORIZED => "Unauthorized",
            Self::FORBIDDEN => "Forbidden",
            Self::UNKNOWN_ATTRIBUTE => "Unknown Attribute",
            Self::ALLOCATION_MISMATCH => "Allocation Mismatch",
            Self::STALE_NONCE => "Stale Nonce",
            Self::ADDRESS_FAMILY_NOT_SUPPORTED => "Address Family Not Supported",
            Self::WRONG_CREDENTIALS => "Wrong Credentials",
            Self::UNSUPPORTED_TRANSPORT_PROTOCOL => "Unsupported Transport Protocol",
            Self::PEER_ADDRESS_FAMILY_MISMATCH => "Peer Address Family Mismatch",
            Self::ALLOCATION_QUOTA_REACHED => "Allocation Quota Reached",
            Self::ROLE_CONFLICT => "Role Conflict",
            Self::SERVER_ERROR => "Server Error",
            Self::INSUFFICIENT_CAPACITY => "Insufficient Capacity",
            _ => "Unknown",
        }
    }

    fn write_into_data(&self, dest: &mut [u8]) -> usize {
        dest[0] = 0u8;
        dest[1] = 0u8;
        dest[2] = (self.code / 100) as u8;
        dest[3] = (self.code % 100) as u8;
        let bytes = self.reason.as_bytes();
        dest[4..4 + bytes.len()].copy_from_slice(bytes);
        4 + bytes.len()
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} '{}'", Self::TYPE, self.code, self.reason)
    }
}

/// The UnknownAttributes [`Attribute`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAttributes {
    attributes: Vec<AttributeType>,
}
impl AttributeStaticType for UnknownAttributes {
    const TYPE: AttributeType = AttributeType(0x000A);
}
impl Attribute for UnknownAttributes {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }
    fn length(&self) -> u16 {
        (self.attributes.len() as u16) * 2
    }
}
impl AttributeWrite for UnknownAttributes {
    fn to_raw(&self) -> RawAttribute {
        let mut data = vec![0; self.length() as usize];
        self.write_into_data(&mut data);
        RawAttribute::new_owned(UnknownAttributes::TYPE, data.into_boxed_slice())
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        let len = self.padded_len();
        let mut offset = self.write_header_unchecked(dest);
        offset += self.write_into_data(&mut dest[offset..]);
        if len - offset > 0 {
            dest[offset..len].fill(0);
        }
    }
}
impl<'a> TryFrom<&RawAttribute<'a>> for UnknownAttributes {
    type Error = StunParseError;

    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.header.atype != Self::TYPE {
            return Err(StunParseError::WrongAttributeImplementation);
        }
        if raw.value.len() % 2 != 0 {
            /* all attributes are 16-bits */
            return Err(StunParseError::Truncated {
                expected: raw.value.len() + 1,
                actual: raw.value.len(),
            });
        }
        let mut attrs = vec![];
        for attr in raw.value.chunks_exact(2) {
            attrs.push(BigEndian::read_u16(attr).into());
        }
        Ok(Self { attributes: attrs })
    }
}
impl UnknownAttributes {
    /// Create a new unknown attributes [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let unknown = UnknownAttributes::new(&[Username::TYPE]);
    /// assert!(unknown.has_attribute(Username::TYPE));
    /// ```
    pub fn new(attrs: &[AttributeType]) -> Self {
        Self {
            attributes: attrs.to_vec(),
        }
    }

    /// Add an [`AttributeType`] that is unsupported
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let mut unknown = UnknownAttributes::new(&[]);
    /// unknown.add_attribute(Username::TYPE);
    /// assert!(unknown.has_attribute(Username::TYPE));
    /// ```
    pub fn add_attribute(&mut self, attr: AttributeType) {
        if !self.has_attribute(attr) {
            self.attributes.push(attr);
        }
    }

    /// Check if an [`AttributeType`] is present
    ///
    /// # Examples
    ///
    /// ```
    /// # use stun_types::attribute::*;
    /// let unknown = UnknownAttributes::new(&[Username::TYPE]);
    /// assert!(unknown.has_attribute(Username::TYPE));
    /// ```
    pub fn has_attribute(&self, attr: AttributeType) -> bool {
        self.attributes.iter().any(|&a| a == attr)
    }

    fn write_into_data(&self, dest: &mut [u8]) -> usize {
        let mut offset = 0;
        for attr in &self.attributes {
            BigEndian::write_u16(&mut dest[offset..offset + 2], (*attr).into());
            offset += 2;
        }
        offset
    }
}

impl std::fmt::Display for UnknownAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", Self::TYPE, self.attributes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::{AlternateServer, Nonce, Realm};
    use tracing::trace;

    #[test]
    fn error_code() {
        let _log = crate::tests::test_init_log();
        let codes = [
            300, 301, 400, 401, 403, 420, 437, 438, 440, 441, 442, 443, 486, 487, 500, 508, 699,
        ];
        for code in codes.iter().copied() {
            let reason = ErrorCode::default_reason_for_code(code);
            let err = ErrorCode::new(code, reason).unwrap();
            trace!("{err}");
            assert_eq!(err.code(), code);
            assert_eq!(err.reason(), reason);
            let raw = RawAttribute::from(&err);
            trace!("{raw}");
            assert_eq!(raw.get_type(), ErrorCode::TYPE);
            let err2 = ErrorCode::try_from(&raw).unwrap();
            assert_eq!(err2.code(), code);
            assert_eq!(err2.reason(), reason);

            let mut dest = vec![0; raw.padded_len()];
            err.write_into(&mut dest).unwrap();
            let raw = RawAttribute::from_bytes(&dest).unwrap();
            let err2 = ErrorCode::try_from(&raw).unwrap();
            assert_eq!(err2.code(), code);
            assert_eq!(err2.reason(), reason);
        }
    }

    fn error_code_new(code: u16) -> ErrorCode {
        let reason = ErrorCode::default_reason_for_code(code);
        ErrorCode::new(code, reason).unwrap()
    }

    #[test]
    fn error_code_parse_short() {
        let _log = crate::tests::test_init_log();
        let err = error_code_new(420);
        let raw = RawAttribute::from(&err);
        // no data
        let mut data: Vec<_> = raw.into();
        let len = 0;
        BigEndian::write_u16(&mut data[2..4], len as u16);
        assert!(matches!(
            ErrorCode::try_from(&RawAttribute::from_bytes(data[..len + 4].as_ref()).unwrap()),
            Err(StunParseError::Truncated {
                expected: 4,
                actual: 0
            })
        ));
    }

    #[test]
    fn error_code_parse_wrong_implementation() {
        let _log = crate::tests::test_init_log();
        let err = error_code_new(420);
        let raw = RawAttribute::from(&err);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            ErrorCode::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn error_code_parse_out_of_range_code() {
        let _log = crate::tests::test_init_log();
        let err = error_code_new(420);
        let raw = RawAttribute::from(&err);
        let mut data: Vec<_> = raw.into();

        // write an invalid error code
        data[6] = 7;
        assert!(matches!(
            ErrorCode::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::InvalidAttributeData)
        ));
    }

    #[test]
    fn error_code_parse_invalid_reason() {
        let _log = crate::tests::test_init_log();
        let err = error_code_new(420);
        let raw = RawAttribute::from(&err);
        let mut data: Vec<_> = raw.into();

        // write an invalid utf8 bytes
        data[10] = 0x88;
        assert!(matches!(
            ErrorCode::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::InvalidAttributeData)
        ));
    }

    #[test]
    fn error_code_build_default_reason() {
        let _log = crate::tests::test_init_log();
        let err = ErrorCode::builder(420).build().unwrap();
        assert_eq!(err.code(), 420);
        assert!(err.reason().len() > 0);
    }

    #[test]
    fn error_code_build_out_of_range() {
        let _log = crate::tests::test_init_log();
        assert!(matches!(
            ErrorCode::builder(700).build(),
            Err(StunWriteError::OutOfRange {
                value: 700,
                min: _,
                max: _
            })
        ));
    }

    #[test]
    fn error_code_new_out_of_range() {
        let _log = crate::tests::test_init_log();
        assert!(matches!(
            ErrorCode::new(700, "some-reason"),
            Err(StunWriteError::OutOfRange {
                value: 700,
                min: _,
                max: _
            })
        ));
    }

    #[test]
    fn unknown_attributes() {
        let _log = crate::tests::test_init_log();
        let mut unknown = UnknownAttributes::new(&[Realm::TYPE]);
        unknown.add_attribute(AlternateServer::TYPE);
        // duplicates ignored
        unknown.add_attribute(AlternateServer::TYPE);
        trace!("{unknown}");
        assert!(unknown.has_attribute(Realm::TYPE));
        assert!(unknown.has_attribute(AlternateServer::TYPE));
        assert!(!unknown.has_attribute(Nonce::TYPE));
        let raw = RawAttribute::from(&unknown);
        assert_eq!(raw.get_type(), UnknownAttributes::TYPE);
        let unknown2 = UnknownAttributes::try_from(&raw).unwrap();
        assert!(unknown2.has_attribute(Realm::TYPE));
        assert!(unknown2.has_attribute(AlternateServer::TYPE));
        assert!(!unknown2.has_attribute(Nonce::TYPE));
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            UnknownAttributes::try_from(
                &RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()
            ),
            Err(StunParseError::Truncated {
                expected: 4,
                actual: 3
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.clone().into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            UnknownAttributes::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));

        let mut dest = vec![0; raw.padded_len()];
        unknown.write_into(&mut dest).unwrap();
        tracing::error!("{dest:?}");
        let raw = RawAttribute::from_bytes(&dest).unwrap();
        let unknown2 = UnknownAttributes::try_from(&raw).unwrap();
        assert!(unknown2.has_attribute(Realm::TYPE));
        assert!(unknown2.has_attribute(AlternateServer::TYPE));
    }
}
