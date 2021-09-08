// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module provides the error definitions and protocols for errors that can occur within
//! the building and parsing of confidential package (.cpk) files.

use thiserror::Error;

/// Specific error types for errors that can occur within the key sharing protocols.
#[derive(Error, Debug)]
pub enum Error {
    /// An error that has been re-badged from the `std::io` subsystem. This kind of error might arise
    /// if there is a low-level problem with package processing, such as the file being too small or
    /// being deleted from disk while it is being processed.
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    /// Error coming from the serde_json crate, which can happen when a manifest JSON
    /// document is improperly formed.
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    /// This kind of error represents a malformation of the package frame or manifest.
    #[error(transparent)]
    PackageError(#[from] PackageErrorKind),

    /// Unknown error.
    #[error("An error occurred for which no further information is available.")]
    Unknown,
}

/// These error variants refer to errors that are raised directly by code in the package module
/// and its submodules, as opposed to errors that are simply being re-badged from underlying subsystems
/// such as I/O.
#[derive(Error, Debug)]
pub enum PackageErrorKind {
    #[error("The package does not begin with the correct 4-byte magic number.")]
    MagicNumberMissing,

    #[error("The package version number is missing or is zero.")]
    PackageVersionMissing,

    #[error("The package version is not supported by this tool.")]
    PackageVersionNotSupported,

    #[error("The package flag field is not valid.")]
    InvalidFlag,

    #[error("The package stream count is zero. Packages must contain at least one stream.")]
    StreamCountZero,

    #[error("The package manifest stream index is out of range.")]
    ManifestStreamOutOfRange,

    #[error("The given stream index is out of range.")]
    StreamIndexOutOfRange,

    #[error("Invalid manifest type.")]
    InvalidManifestType,

    #[error("Invalid manifest version.")]
    InvalidManifestVersion,

    #[error("The given data buffer is the wrong size to hold the bytes of a stream exactly.")]
    BufferSizeIncorrect,
}
