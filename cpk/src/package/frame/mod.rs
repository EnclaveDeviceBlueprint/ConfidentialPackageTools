// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements the package frame, which is the overall binary file format for confidential
//! package (.cpk) files. The frame format consists of a header

pub mod v1;

/// The magic number marker. All confidential package (.cpk) format files begin with this 4-byte sequence
/// in little-endian ordering. The upper bytes are intended to represent Open Enclave Confidential Computing.
pub const MAGIC: u32 = 0x0ECC_F00D;
