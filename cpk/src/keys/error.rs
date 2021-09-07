// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module provides the error definitions and protocols for errors that can occur within
//! key sharing mechanisms.

use thiserror::Error;

/// Specific error types for errors that can occur within the key sharing protocols.
#[derive(Error, Debug)]
pub enum KeyError {
    #[error(transparent)]
    CpmKeyManagementError(#[from] crate::cpm::CpmError),

    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error(transparent)]
    WebRequestError(#[from] reqwest::Error),

    #[error(transparent)]
    Asn1Error(#[from] picky_asn1_der::Asn1DerError),
    
    /// Error emanating from the parsec_client crate. This kind of error can occur
    /// when using Parsec to manage key pairs for wrapping.
    #[error(transparent)]
    ParsecClientError(#[from] parsec_client::error::Error),

    /// Error coming from the RSA crate, which can happen when local memory RSA key
    /// pairs are used as wrapping keys.
    #[error(transparent)]
    RsaError(#[from] rsa::errors::Error),

    /// Error coming from the PKCS1 crate, which can happen when local memory RSA key
    /// pairs are used as wrapping keys.
    #[error(transparent)]
    Pkcs1Error(#[from] pkcs1::Error),

    /// Unknown error.
    #[error("An error occurred for which no further information is available.")]
    Unknown,
}
