// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module defines key sharing protocols that are needed for the production and consumption
//! of confidential packages. The top-level module defines the protocols as traits, and the various
//! sub-modules implement these traits in some useful ways.

pub mod cpm;
pub mod error;
pub mod http;
pub mod parsec;

/// Convenient result alias for this module, where errors are of type [KeyError].
pub type Result<T> = std::result::Result<T, error::KeyError>;

pub trait EncryptionKeySource {
    fn wrap(&self, key_id: &String, public_key: &Vec<u8>) -> Result<Vec<u8>>;
}

pub trait EncryptionKeyDestination {
    fn unwrap(&self, key_id: &String, wrapped: &Vec<u8>) -> Result<()>;
}

pub trait EncryptionKeyExposure {
    fn expose(&self, wrapped: &Vec<u8>) -> Result<Vec<u8>>;
}

pub trait WrappingKeySource {
    fn get_public(&self) -> Result<Vec<u8>>;
}

pub trait WrappingKeyDestination {
    fn publish_public(&self, wrapping_key: &Vec<u8>) -> Result<()>;
}
