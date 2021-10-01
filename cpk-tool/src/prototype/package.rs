// SPDX-License-Identifier: MIT
// Copyright 2021 Contributors to the Confidential Packaging project.

//! Prototype (proof-of-concept) implementation of a data model for confidential packages.

use crate::error::{Error, Result, ToolErrorKind};
use cpk::cpm::ConfidentialPackageManager;
use cpk::package::frame::Frame;
use cpk::package::manifest::{
    CertificationScheme, DigestScheme, EncryptionScheme, Manifest, SigningScheme,
};
use std::convert::TryInto;
use std::fs::File;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

/// Very simple data model for the confidential package, as used by [installer::simple_install_from_file]. This structure
/// is a placeholder for more comprehensive and flexible data models that will eventually exist in the `cpk`
/// crate.
#[derive(Debug)]
pub struct ConfidentialPackage {
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
    pub fn build_from_frame_and_manifest(
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
    pub fn install_to(
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
    pub fn verify_in(&self, cpm: &ConfidentialPackageManager) -> Result<(bool, bool)> {
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
