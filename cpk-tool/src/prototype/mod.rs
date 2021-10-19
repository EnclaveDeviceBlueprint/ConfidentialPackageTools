// SPDX-License-Identifier: MIT
// Copyright 2021 Contributors to the Confidential Packaging project.

//! This module contains prototype (proof-of-concept) implementations of tooling facilities
//! for confidential packaging.
//! 
//! The code in this module is intended to be temporary and used for PoC or demonstration
//! deployments only. The functionality provided here will eventually be expanded and improved
//! so that it can be housed in the `cpk` crate in support of the command-line tools and any other
//! clients that need to create or process confidential packages.
//! 
//! This module includes a very simple and restricted implementation of a data model for the
//! confidential package, and has the ability to process small, simple packages whose features
//! fall within the boundaries of those restrictions. It is also able to build simple packages from
//! a given payload, subject to those same simplifications and restrictions.

#[cfg(feature = "build")]
pub mod builder;
#[cfg(feature = "install")]
pub mod installer;
#[cfg(any(feature = "build", feature = "install"))]
pub mod package;
