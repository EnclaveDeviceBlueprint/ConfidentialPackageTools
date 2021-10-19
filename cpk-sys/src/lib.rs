// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! # FFI Definitions for the Confidential Package Manager (CPM).
//! 
//! The CPM behaves according to a contract that is defined using OpenEnclave's Enclave Definition Language (EDL),
//! from which C function prototypes can be derived. This crate's build process is therefore a double-step generation
//! process, where OpenEnclave's `oeedger8r` tool is first used to generate the C code from the EDL contracts, and
//! then `bindgen` is used to generate the Rust FFI bindings from the C code.
//! 
//! This crate also provides a user-space simulator for the CPM, which allows any client of the CPM to be tested to
//! a rudimentary level without requiring any dependencies on OpenEnclave or its tools, and without requiring a
//! runtime environment that supports enclaves. Build this crate with the feature `cpm-simulator` to get this
//! behaviour. Note that the simulator is quite crude and has several limitations.

#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    trivial_casts,
    deref_nullptr,
    clippy::all
)]

mod cpm_bindings {
    #[cfg(feature = "cpm-simulator")]
    include!(concat!(env!("OUT_DIR"), "/cpmsim_bindings.rs"));

    #[cfg(not(feature = "cpm-simulator"))]
    include!(concat!(env!("OUT_DIR"), "/confidential_package_specification_bindings.rs"));
}

// Just re-export everything that bindgen creates. Possibly this could be slimmed down to a subset.
pub use cpm_bindings::*;
