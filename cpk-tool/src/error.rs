// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Error definitions/handling.

use thiserror::Error;

/// Errors in cpk-tool
#[derive(Error, Debug)]
pub enum Error {
    /// Error emanating from standard I/O.
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    /// Errors resulting from failing calls to the Confidential Package Manager (CPM).
    #[error(transparent)]
    #[cfg(any(feature = "sync", feature = "install"))]
    CpmError(#[from] cpk::cpm::CpmError),

    /// Errors coming from the package file processing, due to the package being unreadable or
    /// malformed in some way.
    #[error(transparent)]
    PackageProcessingError(#[from] cpk::package::error::Error),

    /// Errors relating to the wrapping or distribution of encryption keys.
    #[error(transparent)]
    #[cfg(any(feature = "sync", feature = "build"))]
    KeySharingError(#[from] cpk::keys::error::KeyError),

    /// Errors relating to JSON processing.
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    /// Errors related to RSA operations
    #[error(transparent)]
    RsaError(#[from] rsa::errors::Error),

    /// Error emanating from the cpk-tool itself.
    #[error(transparent)]
    ToolError(#[from] ToolErrorKind),
}

/// Errors originating in the cpk-tool itself.
#[derive(Error, Debug)]
pub enum ToolErrorKind {
    /// Operation not supported by the cpk-tool
    #[error("Operation not supported by the cpk-tool")]
    NotSupported,

    /// This occurs when the confidential package has been built with an encryption scheme that is
    /// not recognised or supported by the tool.
    #[error("Unsupported payload encryption scheme")]
    UnsupportedEncryptionScheme,

    /// This occurs when the confidential package digest is using an unrecognised or unsupported
    /// hashing algorithm.
    #[error("Unsupported digest scheme")]
    UnsupportedDigestScheme,

    /// This occurs when the confidential package has been signed using an unrecognised or
    /// unsupported signature algorithm.
    #[error("Unsupported signature scheme")]
    UnsupportedSignatureScheme,

    /// This occurs when the confidential application is using an unsupported method of providing the
    /// public key certificate for digital signature verification.
    #[error("Unsupported certification scheme")]
    UnsupportedCertificationScheme,

    /// Invalid `method` argument passed to the `sync` command. The sync method must be either
    /// `http` or `azuretwin`.
    #[error("Invalid method given for the sync command")]
    InvalidSyncMethod,

    /// There is some missing configuration for a command, such as a required environment variable or
    /// configuration file/option.
    #[error("Missing configuration")]
    MissingConfiguration,

    /// Invalid encryption key source/method specified. Currently, encryption keys need to come from a web
    /// front-end to a key vault ("http"), or from a local file on disk ("file").
    #[error("Invalid encryption key source")]
    InvalidEncryptionKeySource,

    /// Invalid wrapping key source specified.
    ///
    /// Wrapping keys are used to wrap the encryption key when it is retrieved from the key store. Wrapping
    /// keys can come from the CPM (as is always the case when synchronizing keys), or they can come
    /// from either Parsec or just local memory (when building confidential packages).
    #[error("Invalid wrapping key source")]
    InvalidWrappingKeySource,
}

/// A Result type with the Err variant set as a ToolError
pub type Result<T> = std::result::Result<T, Error>;
