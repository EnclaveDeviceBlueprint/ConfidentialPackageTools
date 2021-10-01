// SPDX-License-Identifier: MIT
// Copyright 2021 Contributors to the Confidential Packaging project.

//! Prototype (proof-of-concept) implementation of the confidential package installer
//! process.

use crate::error::Result;
use crate::prototype::package::ConfidentialPackage;
use cpk::cpm::ConfidentialPackageManager;
use cpk::package::frame::Frame;
use cpk::package::manifest::Manifest;
use std::fs::File;

/// A minimal, restricted implementation of the installation process.
///
/// In time, the `cpk` crate will offer an installation service, and the install command
/// can make calls into that service. This is a simplified, temporary implementation for
/// the install command. It is entirely valid, and can handle real .cpk files, but it makes a
/// number of assumptions, as follows:
///
/// - All output can simply be written to the console with the `println!()` macro.
/// - The package is of sufficiently modest size that all of its data streams can be loaded
///   eagerly into memory. The .cpk file format itself is deliberately designed to avoid this need,
///   but dealing with larger files on a block-by-block basis would require more complex code
///   in the installer.
/// - The payload is encrypted with the AES-GCM scheme.
/// - The payload is signed using an RSA PKCS1 v 1.5 key, and the certificate is an embedded PEM
///   X509 document that is self-signed.
/// - Only the payload is hashed and signed. This function does not handle hashes or signatures that
///   apply across multiple package streams.
pub fn simple_install_from_file(filepath: &String) -> Result<()> {
    let mut file = File::open(filepath)?;

    // Parse the CPK frame.
    println!("Opening package...");
    let frame = Frame::read_from_stream(&mut file)?;

    // Get the manifest stream out.
    let mut manifest_bytes: Vec<u8> = Vec::new();
    frame.read_whole_manifest_stream_into_vec(&mut file, &mut manifest_bytes)?;

    // Parse the manifest
    println!(
        "Reading package manifest (stream {})...",
        frame.header.manifest_stream
    );
    let manifest = Manifest::from_bytes(manifest_bytes.as_slice())?;

    // Report manifest summary to the console.
    println!("Package identity: {}", &manifest.cp_id);
    println!("Package name: {}", &manifest.cp_name);
    println!("Package vendor: {}", &manifest.cp_vendor);
    println!("    Target architecture: {}", &manifest.payload.target.arch);
    println!(
        "    Target operating system: {}",
        &manifest.payload.target.os
    );
    println!(
        "    Version {}.{}.{} ({})",
        &manifest.payload.ver.maj,
        &manifest.payload.ver.min,
        &manifest.payload.ver.rev,
        &manifest.payload.ver.date
    );

    println!("Processing package contents...");
    let package = ConfidentialPackage::build_from_frame_and_manifest(&mut file, &frame, &manifest)?;

    println!("Connecting with Confidential Package Manager on the host system...");
    let cpm = ConfidentialPackageManager::new();
    let _pingres = cpm.ping()?;

    println!("Installing...");
    package.install_to(&cpm)?;

    println!("Verifying...");
    let (dig_check, sig_check) = package.verify_in(&cpm)?;

    println!("    Digest check {}.", {
        if dig_check {
            "PASSED"
        } else {
            "FAILED"
        }
    });
    println!("    Signature check {}.", {
        if sig_check {
            "PASSED"
        } else {
            "FAILED"
        }
    });

    println!("Finished.");
    Ok(())
}
