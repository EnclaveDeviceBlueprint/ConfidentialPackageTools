// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module provides the error definitions and protocols for errors that can occur within
//! the building and parsing of confidential package (.cpk) files.

use thiserror::Error;

/// Specific error types for errors that can occur within the key sharing protocols.
#[derive(Error, Debug)]
pub enum PackageError { 
    /// Unknown error.
    #[error("An error occurred for which no further information is available.")]
    Unknown,
}
