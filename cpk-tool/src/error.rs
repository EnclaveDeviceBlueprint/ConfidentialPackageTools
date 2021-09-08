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
    CpmError(#[from] cpk::cpm::CpmError),

    /// Errors coming from the package file processing, due to the package being unreadable or
    /// malformed in some way.
    #[error(transparent)]
    PackageProcessingError(#[from] cpk::package::error::Error),

    /// Errors relating to the wrapping or distribution of encryption keys.
    #[error(transparent)]
    KeySharingError(#[from] cpk::keys::error::KeyError),

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
}

/// A Result type with the Err variant set as a ToolError
pub type Result<T> = std::result::Result<T, Error>;
