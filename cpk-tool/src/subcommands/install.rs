// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Installs a confidential package on the host system from the given
//! input file.

use crate::error::Result;
use cpk::cpm::ConfidentialPackageManager;
use cpk::package::frame::Frame;
use cpk::package::manifest::Manifest;
use std::fs::File;
use structopt::StructOpt;

/// Models the options required by the install command.
#[derive(Debug, StructOpt)]
pub struct Install {
    /// The input file, which must be a binary confidential package file.
    #[structopt(short = "p", long = "package")]
    package_path: String,
}

/// A simple implementation of the installation process.
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
/// - The decryption key needs to be explicitly wrapped from a web contract source. The
///   `CP_CLOUD_KEY_SOURCE` environment variable needs to hold a reference to a suitable
///    URL that will implement the HTTP web contract for key wrapping.
/// - Only the payload is hashed and signed. This function does not handle hashes or signatures that
///   apply across multiple package streams.
fn simple_install_from_file(filepath: &String) -> Result<()> {
    let mut file = File::open(filepath)?;

    // Connect to the CPM
    println!("Connecting to Confidential Package Manager on ths host system...");
    let cpm = ConfidentialPackageManager::new();
    let _pingres = cpm.ping()?;

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

    // Report manifest summary
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

    Ok(())
}

impl Install {
    /// Installs the confidential package on the host system from the given
    /// input file.
    pub fn run(&self) -> Result<()> {
        simple_install_from_file(&self.package_path)
    }
}
