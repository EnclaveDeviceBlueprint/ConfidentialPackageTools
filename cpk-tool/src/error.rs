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

    /// Error emanating from the base64 crate.
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
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
