// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements the confidential package file format.
//! 
//! Confidential packages are structured in a binary file format called a `frame`, which is just a collection
//! of numbered object streams, with a simple header to tell the consumer the seek position within the file at which
//! each stream can be found, and also the length of each stream.
//! 
//! One of the streams in the package must be a `manifest`, which is a JSON document. The manifest provides the full
//! description of the package, and describes how the consumer must use the data in the various streams to
//! install or update a confidential application.

pub mod frame;
pub mod manifest;
pub mod error;

/// Convenient result alias for this module.
pub type Result<T> = std::result::Result<T, error::Error>;
