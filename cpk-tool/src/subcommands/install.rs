// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Installs a confidential package on the host system from the given
//! input file.

use crate::error::{Error, Result, ToolErrorKind};
use cpk::cpm::ConfidentialPackageManager;
use cpk::package::frame::Frame;
use cpk::package::manifest::{
    CertificationScheme, DigestScheme, EncryptionScheme, Manifest, SigningScheme,
};
use std::convert::TryInto;
use std::fs::File;
use structopt::StructOpt;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

/// Models the options required by the install command.
#[derive(Debug, StructOpt)]
pub struct Install {
    /// The input file, which must be a binary confidential package (.cpk) file.
    #[structopt(short = "p", long = "package")]
    package_path: String,
}

/// Very simple data model for the confidential package, as used by [simple_install_from_file]. This structure
/// is a placeholder for more comprehensive and flexible data models that will eventually exist in the `cpk`
/// crate.
struct ConfidentialPackage {
    /// The identity of the application being installed, which is also the lookup used by the CPM to map the
    /// application to its correct encryption key.
    application_id: String,

    /// The AES-GCM encrypted payload to be installed.
    encrypted_payload: Vec<u8>,

    /// The strength of the AES encryption key, in bits.
    encryption_key_strength: u32,

    /// The name of the encryption key at its source.
    encryption_key_name: String,

    /// The nonce for the AES-GCM decryption process.
    nonce: Vec<u8>,

    /// The auth tag for the decryption process.
    tag: Vec<u8>,

    /// The SHA-256 digest of the original payload (before it was encrypted).
    digest: Vec<u8>,

    /// The RSA PKCS1v15 signature of the payload digest.
    signature: Vec<u8>,

    /// The strength, in bits, of the signing key.
    signature_key_strength: u32,

    /// The public cert for signature verification, which is assumed to be in PEM format.
    cert: Vec<u8>,
}

impl ConfidentialPackage {
    /// Creates an "empty" confidential package model, ready to be populated with content from the package
    /// frame, guided by the manifest.
    fn new(application_id: &String) -> ConfidentialPackage {
        ConfidentialPackage {
            application_id: application_id.clone(),
            encrypted_payload: Vec::new(),
            encryption_key_strength: 0,
            encryption_key_name: String::from(""),
            nonce: Vec::new(),
            tag: Vec::new(),
            digest: Vec::new(),
            signature: Vec::new(),
            signature_key_strength: 0,
            cert: Vec::new(),
        }
    }

    /// Populates the model from the package frame, guided by the directives in the manifest.
    fn build_from_frame_and_manifest(
        file: &mut File,
        frame: &Frame,
        manifest: &Manifest,
    ) -> Result<ConfidentialPackage> {
        let mut package = ConfidentialPackage::new(&manifest.cp_id);

        // Get the main data stream - the encrypted package.
        frame.read_whole_stream_into_vec(
            manifest.payload.data,
            file,
            &mut package.encrypted_payload,
        )?;

        // Handle only AES-GCM encryption
        match &manifest.payload.enc {
            EncryptionScheme::AesGcm {
                key_name,
                key_strength,
                nonce,
                tag,
            } => {
                frame.read_whole_stream_into_vec(*nonce, file, &mut package.nonce)?;
                frame.read_whole_stream_into_vec(*tag, file, &mut package.tag)?;
                package.encryption_key_strength = *key_strength as u32;
                package.encryption_key_name = key_name.clone();
            }
            _ => return Err(Error::ToolError(ToolErrorKind::UnsupportedEncryptionScheme)),
        };

        match &manifest.payload.dig {
            DigestScheme::Sha256 { data } => {
                frame.read_whole_stream_into_vec(*data, file, &mut package.digest)?;
            }
            _ => return Err(Error::ToolError(ToolErrorKind::UnsupportedDigestScheme)),
        };

        match &manifest.payload.sig {
            SigningScheme::RsaPkcs1v15 { key_strength, data } => {
                frame.read_whole_stream_into_vec(*data, file, &mut package.signature)?;
                package.signature_key_strength = *key_strength as u32;
            }
            _ => return Err(Error::ToolError(ToolErrorKind::UnsupportedSignatureScheme)),
        };

        match &manifest.payload.cert {
            CertificationScheme::EmbeddedX509Pem { data } => {
                frame.read_whole_stream_into_vec(*data, file, &mut package.cert)?;
            }
            _ => {
                return Err(Error::ToolError(
                    ToolErrorKind::UnsupportedCertificationScheme,
                ))
            }
        };

        Ok(package)
    }

    /// Installs the package into the CPM or CPM simulator (depending on cargo feature settings).
    fn install_to(
        &self,
        cpm: &ConfidentialPackageManager,
    ) -> Result<()> {
        cpm.begin_application_deployment(
            &self.application_id,
            self.encrypted_payload.len().try_into().unwrap(),
        )?;
        cpm.initialize_decryption_aes_gcm(
            &self.application_id,
            self.encryption_key_strength,
            &self.nonce,
            &self.tag,
        )?;
        cpm.add_application_data(&self.application_id, &self.encrypted_payload)?;
        Ok(())
    }

    /// Verifies the package digest and signature using the CPM or CPM simulator (depending on cargo
    /// feature settings).
    ///
    /// The result is a pair of booleans. The first boolean indicates whether the digest check passed, and
    /// the second indicates whether the signature check passed. (If the first flag is false, then the
    /// second flag must also be false, because it would not be possible to even attempt the signature check
    /// if the digest is wrong).
    fn verify_in(&self, cpm: &ConfidentialPackageManager) -> Result<(bool, bool)> {
        // TODO: Not handling X509 parse errors here, but this code is temporary, pending deeper integration
        // of the installation process into the cpk crate.
        let (_rem, pem) = parse_x509_pem(&self.cert).unwrap();
        let (_, cert) = parse_x509_certificate(&pem.contents).unwrap();
        let pki = cert.public_key();
        let pk = pki.subject_public_key.data.to_vec();

        // Call the CPM to verify, because only the CPM has the plaintext content.
        let (dig_check, sig_check) = cpm.verify_application_sha256_rsa_pkcs1_v15(
            &self.application_id,
            self.signature_key_strength,
            &self.digest,
            &self.signature,
            &pk,
        )?;

        // This is the final operation, so one last call to close off the process with the CPM.
        cpm.end_application_deployment(&self.application_id)?;

        Ok((dig_check, sig_check))
    }
}

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
/// - The decryption key needs to be explicitly wrapped from a web contract source. The
///   `CP_CLOUD_KEY_SOURCE` environment variable needs to hold a reference to a suitable
///    URL that will implement the HTTP web contract for key wrapping.
/// - Only the payload is hashed and signed. This function does not handle hashes or signatures that
///   apply across multiple package streams.
fn simple_install_from_file(filepath: &String) -> Result<()> {
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

impl Install {
    /// Installs the confidential package on the host system from the given
    /// input file.
    pub fn run(&self) -> Result<()> {
        simple_install_from_file(&self.package_path)
    }
}
