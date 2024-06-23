// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use byteorder::{BigEndian, ByteOrder};

use crate::message::{StunParseError, TransactionId, MAGIC_COOKIE};

use super::{check_len, AttributeType, RawAttribute};

/// The address family of the socket
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    IPV4,
    IPV6,
}

impl AddressFamily {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            AddressFamily::IPV4 => 0x1,
            AddressFamily::IPV6 => 0x2,
        }
    }

    pub(crate) fn from_byte(byte: u8) -> Result<AddressFamily, StunParseError> {
        match byte {
            0x1 => Ok(AddressFamily::IPV4),
            0x2 => Ok(AddressFamily::IPV6),
            _ => Err(StunParseError::InvalidAttributeData),
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressFamily::IPV4 => write!(f, "IPV4"),
            AddressFamily::IPV6 => write!(f, "IPV6"),
        }
    }
}

/// Helper struct for `SocketAddr`s that are stored is an attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedSocketAddr {
    addr: SocketAddr,
}

impl MappedSocketAddr {
    /// Create a new [`MappedSocketAddr`].
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// The number of bytes of this [`MappedSocketAddr`].
    pub fn length(&self) -> u16 {
        match self.addr {
            SocketAddr::V4(_) => 8,
            SocketAddr::V6(_) => 20,
        }
    }

    /// Convert this [`MappedSocketAddr`] into a [`RawAttribute`]
    pub fn to_raw<'a>(&self, atype: AttributeType) -> RawAttribute<'a> {
        match self.addr {
            SocketAddr::V4(addr) => {
                let mut buf = [0; 8];
                buf[1] = AddressFamily::IPV4.to_byte();
                BigEndian::write_u16(&mut buf[2..4], addr.port());
                let octets = u32::from(*addr.ip());
                BigEndian::write_u32(&mut buf[4..8], octets);
                RawAttribute::new(atype, &buf).into_owned()
            }
            SocketAddr::V6(addr) => {
                let mut buf = [0; 20];
                buf[1] = AddressFamily::IPV6.to_byte();
                BigEndian::write_u16(&mut buf[2..4], addr.port());
                let octets = u128::from(*addr.ip());
                BigEndian::write_u128(&mut buf[4..20], octets);
                RawAttribute::new(atype, &buf).into_owned()
            }
        }
    }

    /// Try to convert a [`RawAttribute`] into a [`MappedSocketAddr`]
    pub fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        if raw.value.len() < 4 {
            return Err(StunParseError::Truncated {
                expected: 4,
                actual: raw.value.len(),
            });
        }
        let port = BigEndian::read_u16(&raw.value[2..4]);
        let family = AddressFamily::from_byte(raw.value[1])?;
        let addr = match family {
            AddressFamily::IPV4 => {
                // ipv4
                check_len(raw.value.len(), 8..=8)?;
                IpAddr::V4(Ipv4Addr::from(BigEndian::read_u32(&raw.value[4..8])))
            }
            AddressFamily::IPV6 => {
                // ipv6
                check_len(raw.value.len(), 20..=20)?;
                let mut octets = [0; 16];
                octets.clone_from_slice(&raw.value[4..]);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        Ok(Self {
            addr: SocketAddr::new(addr, port),
        })
    }

    /// The `SocketAddr` in this [`MappedSocketAddr`]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl std::fmt::Display for MappedSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.addr {
            SocketAddr::V4(addr) => write!(f, "{:?}", addr),
            SocketAddr::V6(addr) => write!(f, "{:?}", addr),
        }
    }
}

/// Helper struct for [`SocketAddr`] that are stored as an
/// [`Attribute`](crate::attribute::Attribute) after an XOR operation with the [`TransactionId`]
/// of a [`Message`](crate::message::Message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorSocketAddr {
    pub addr: MappedSocketAddr,
}

impl XorSocketAddr {
    /// Create a new [`XorSocketAddr`].
    pub fn new(addr: SocketAddr, transaction: TransactionId) -> Self {
        Self {
            addr: MappedSocketAddr::new(XorSocketAddr::xor_addr(addr, transaction)),
        }
    }

    /// The number of bytes of this [`XorSocketAddr`].
    pub fn length(&self) -> u16 {
        self.addr.length()
    }

    /// Convert this [`XorSocketAddr`] into a [`RawAttribute`]
    pub fn to_raw<'a>(&self, atype: AttributeType) -> RawAttribute<'a> {
        self.addr.to_raw(atype)
    }

    /// Try to convert a [`RawAttribute`] into a [`XorSocketAddr`]
    pub fn from_raw(raw: &RawAttribute) -> Result<Self, StunParseError> {
        let addr = MappedSocketAddr::from_raw(raw)?;
        Ok(Self { addr })
    }

    pub fn xor_addr(addr: SocketAddr, transaction: TransactionId) -> SocketAddr {
        match addr {
            SocketAddr::V4(addr) => {
                let port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
                let const_octets = MAGIC_COOKIE.to_be_bytes();
                let addr_octets = addr.ip().octets();
                let octets = bytewise_xor!(4, const_octets, addr_octets, 0);
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
            }
            SocketAddr::V6(addr) => {
                let port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
                let transaction: u128 = transaction.into();
                let const_octets = ((MAGIC_COOKIE as u128) << 96
                    | (transaction & 0x0000_0000_ffff_ffff_ffff_ffff_ffff_ffff))
                    .to_be_bytes();
                let addr_octets = addr.ip().octets();
                let octets = bytewise_xor!(16, const_octets, addr_octets, 0);
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
            }
        }
    }

    pub(crate) fn addr(&self, transaction: TransactionId) -> SocketAddr {
        XorSocketAddr::xor_addr(self.addr.addr(), transaction)
    }
}

impl std::fmt::Display for XorSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.addr.addr() {
            SocketAddr::V4(_) => write!(f, "{:?}", self.addr(0x0.into())),
            SocketAddr::V6(addr) => write!(f, "XOR({:?})", addr),
        }
    }
}
