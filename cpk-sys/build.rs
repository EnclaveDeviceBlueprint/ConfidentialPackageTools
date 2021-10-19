// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

#![deny(
    nonstandard_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]
// This one is hard to avoid.
#![allow(clippy::multiple_crate_versions)]

use std::io::{Error, ErrorKind, Result};

#[cfg(feature = "cpm-simulator")]
fn bind_to_cpm_simulator() -> Result<()> {
    // The CPM simulator code is included in this crate.
    let cpm_simulator_path = "./src/c";

    // The CPM simulator depends on crypto functionality from Mbed TLS, which you need to have
    // cloned and built yourself. MBED_TLS_PATH should point to the root of the cloned repo.
    let mbed_var = std::env::var("MBED_TLS_PATH");

    if mbed_var.is_err() {
        return Err(Error::new(ErrorKind::Other,
            "MBED_TLS_PATH environment variable is not set. Please clone Mbed TLS from its repository at https://github.com/ARMmbed/mbedtls and build it with 'make'. Set MBED_TLS_PATH to its top-level folder."));
    }

    let mbed_tls_path = mbed_var.unwrap();
    let mbed_inc_dir = mbed_tls_path.clone() + &"/include/";
    let output_dir = std::env::var("OUT_DIR").unwrap();

    // Create rust bindings from the CPM header file.
    // For all intents and purposes, this header file is precisely what oeedger8r generates for the REE/TEE CPM
    // contract, so any Rust code that drives these operations should work the same way in the "real world".
    let bindings = bindgen::Builder::default()
        .header(format!(
            "{}{}",
            cpm_simulator_path, "/ConfidentialPackageSpecification_u.h"
        ))
        .clang_arg(format!("{}{}", "-I", cpm_simulator_path))
        // Tell cargo to invalidate the built crate whenever any  of the included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .map_err(|_| {
            Error::new(
                ErrorKind::Other,
                "Unable to generate bindings for the CPM simulator.",
            )
        })?;

    bindings.write_to_file(format!("{}{}", output_dir, "/cpmsim_bindings.rs"))?;

    // Use the `cc` crate to build the CPM simulator and statically link it.
    cc::Build::new()
        .file(format!("{}{}", cpm_simulator_path, "/cpmsim.c"))
        .include(cpm_simulator_path)
        .include(mbed_inc_dir)
        .static_flag(true)
        .compile("libcpmsim.a");
    // We need to link mbedcrypto as well - we assume that this is built and available relative to MBED_TLS_PATH.
    // Again, it's a static link.
    // We need this because the simulator uses mbedcrypto in place of the TEE.
    println!("cargo:rustc-link-search=native={}/library", mbed_tls_path);
    println!("cargo:rustc-link-lib=static=mbedcrypto");
    
    Ok(())
}

#[cfg(not(feature = "cpm-simulator"))]
fn bind_to_cpm() -> Result<()> {
    // Create paths used for OE based on environement variable
    let oe_package_var = std::env::var("OE_PACKAGE_PREFIX");

    if oe_package_var.is_err() {
        return Err(Error::new(
            ErrorKind::Other,
            "Please set the OE_PACKAGE_PREFIX environment variable.",
        ));
    }

    let oe_package_prefix = oe_package_var.unwrap();
    let oe_inc_dir = oe_package_prefix.clone() + &"/include/";
    let oe_lib_dir = oe_package_prefix.clone() + &"/lib/openenclave/host/";
    let output_dir = std::env::var("OUT_DIR").unwrap();
    let opteec_dir =oe_package_prefix.clone() + &"/lib/openenclave/optee/libteec/";

    let cps_var = std::env::var("CPS_DIR");

    if cps_var.is_err() {
        return Err(Error::new(
            ErrorKind::Other,
            "Please set the CPS_DIR environment variable.",
        ));
    }
    let cps_dir = cps_var.unwrap();

    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed={}/ConfidentialPackageSpecification.edl", cps_dir);

    // TODO: This EDL file is coming from outside of the repo. We should probably bring it in as a Git submodule.
    let _res = std::process::Command::new("oeedger8r")
        .arg("--untrusted")
        .arg(format!("{}/ConfidentialPackageSpecification.edl", cps_dir))
        .arg("--untrusted-dir")
        .arg(output_dir.clone())
        .spawn()
        .map_err(|_| {
            Error::new(
                ErrorKind::Other,
                "Failed to execute the oeedger8r program to generate C code from the OE EDL contract.",
            )
        })?;

    // Pull in oehost library
    println!("cargo:rustc-link-lib=oehost");
    println!("{}{}", "cargo:rustc-link-search=", oe_lib_dir);
    println!("{}{}", "cargo:rustc-link-search=", oe_inc_dir);
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=openenclave/host.h");

    let bindings = bindgen::Builder::default()
        .header(format!("{}{}", oe_inc_dir, "/openenclave/host.h"))
        .header(format!(
            "{}{}",
            output_dir, "/ConfidentialPackageSpecification_u.h"
        ))
        .clang_arg(format!("{}{}", "-I", oe_inc_dir))
        .clang_arg("-target")
        .clang_arg("aarch64-unknown-linux-gnu")
        // Tell cargo to invalidate the built crate whenever any  of the included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .map_err(|_| {
            Error::new(
                ErrorKind::Other,
                "Unable to generate bindings for the Confidential Package Manager.",
            )
        })?;

    bindings.write_to_file(format!(
        "{}{}",
        output_dir, "/confidential_package_specification_bindings.rs"
    ))?;

    // Use the `cc` crate to build a C file and statically link it.
    cc::Build::new()
        .file(format!(
            "{}{}",
            output_dir, "/ConfidentialPackageSpecification_u.c"
        ))
        .include(oe_inc_dir)
        .static_flag(true)
        .compile("libConfidentialPackageSpecification.a");

    // Pull in oehost library
    println!("cargo:rustc-link-lib=oehost");
    println!("{}{}", "cargo:rustc-link-search=", oe_lib_dir);

    // Pull in OPTEE Client library
    println!("cargo:rustc-link-lib=teec");
    println!("{}{}", "cargo:rustc-link-search=", opteec_dir);
    
    Ok(())
}

fn main() -> Result<()> {
    #[cfg(feature = "cpm-simulator")]
    return bind_to_cpm_simulator();
    #[cfg(not(feature = "cpm-simulator"))]
    return bind_to_cpm();
}
