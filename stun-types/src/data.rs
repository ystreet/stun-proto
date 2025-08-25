// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Data handling
//!
//! Provides a CoW interface for slices of `[u8]` and `Box<[u8]>`

use alloc::boxed::Box;

/// A slice of data
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct DataSlice<'a>(&'a [u8]);

impl<'a> DataSlice<'a> {
    /// Consume this slice and return the underlying data.
    pub fn take(self) -> &'a [u8] {
        self.0
    }

    /// Copy this borrowed slice into a new owned allocation.
    pub fn to_owned(&self) -> DataOwned {
        DataOwned(self.0.into())
    }
}

impl core::ops::Deref for DataSlice<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> From<DataSlice<'a>> for &'a [u8] {
    fn from(value: DataSlice<'a>) -> Self {
        value.0
    }
}

impl<'a> From<&'a [u8]> for DataSlice<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}

/// An owned piece of data
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct DataOwned(Box<[u8]>);

impl DataOwned {
    /// Consume this slice and return the underlying data.
    pub fn take(self) -> Box<[u8]> {
        self.0
    }
}

impl core::ops::Deref for DataOwned {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<DataOwned> for Box<[u8]> {
    fn from(value: DataOwned) -> Self {
        value.0
    }
}

impl From<Box<[u8]>> for DataOwned {
    fn from(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

/// An owned or borrowed piece of data
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data<'a> {
    /// Borrowed data.
    Borrowed(DataSlice<'a>),
    /// Owned data.
    Owned(DataOwned),
}

impl core::ops::Deref for Data<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(data) => data.0,
            Self::Owned(data) => &data.0,
        }
    }
}

impl Data<'_> {
    /// Create a new owned version of this data
    pub fn into_owned<'b>(self) -> Data<'b> {
        match self {
            Self::Borrowed(data) => Data::Owned(data.to_owned()),
            Self::Owned(data) => Data::Owned(data),
        }
    }
}

impl<'a> From<&'a [u8]> for Data<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Borrowed(value.into())
    }
}

impl From<Box<[u8]>> for Data<'_> {
    fn from(value: Box<[u8]>) -> Self {
        Self::Owned(value.into())
    }
}

impl AsRef<[u8]> for Data<'_> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn data_access() {
        let _log = crate::tests::test_init_log();
        let array = [0, 1, 2, 3];
        let borrowed_data = Data::from(array.as_slice());
        assert_eq!(array.as_slice(), &*borrowed_data);
        let owned_data = borrowed_data.into_owned();
        assert_eq!(array.as_slice(), &*owned_data);
        let Data::Owned(owned) = owned_data else {
            unreachable!();
        };
        let inner = <Box<[u8]>>::from(owned.clone());
        assert_eq!(array.as_slice(), &*inner);
        let owned = DataOwned::take(owned);
        assert_eq!(array.as_slice(), &*owned);
        let data = Data::from(owned);
        assert_eq!(array.as_slice(), &*data);
        let borrowed = DataSlice::from(&*data);
        assert_eq!(array.as_slice(), &*borrowed);
        let inner = <&[u8]>::from(borrowed.clone());
        assert_eq!(array.as_slice(), inner);
        let inner = borrowed.take();
        assert_eq!(array.as_slice(), inner);
    }
}
