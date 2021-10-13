// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! The cpk crate contains the functionality required to read, write, build and interpret files that adopt
//! the Confidential Package (.cpk) file format.

#[cfg(feature = "cpm")]
pub mod cpm;

#[cfg(feature = "key-management")]
pub mod keys;

pub mod package;
