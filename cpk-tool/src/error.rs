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
