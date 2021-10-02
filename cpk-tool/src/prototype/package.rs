// SPDX-License-Identifier: MIT
// Copyright 2021 Contributors to the Confidential Packaging project.

//! Prototype (proof-of-concept) implementation of a data model for confidential packages.

use crate::error::{Error, Result, ToolErrorKind};
use cpk::cpm::ConfidentialPackageManager;
use cpk::package::frame::{Frame, MAGIC};
use cpk::package::manifest::{
    CertificationScheme, DigestScheme, EncryptionScheme, Manifest, Package, Payload, SigningScheme,
    Target, Version,
};
use std::convert::TryInto;
use std::fs::File;
use std::io::Write;
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

    /// The human-readable name of the application.
    application_name: String,

    /// The application's vendor description.
    vendor: String,

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
    fn new(
        application_id: &String,
        application_name: &String,
        vendor: &String,
    ) -> ConfidentialPackage {
        ConfidentialPackage {
            application_id: application_id.clone(),
            application_name: application_name.clone(),
            vendor: vendor.clone(),
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

    /// Builds a confidential package model from a pre-prepared set of encrypted input and other
    /// component parts.
    ///
    /// Input is assumed to be AES-256 in GCM mode with the given nonce and tag.
    ///
    /// Digest is assumed to be SHA-256.
    ///
    /// Signature is assumed to be RSA-2048 PKCS1 v1.5.
    ///
    /// Certificate is assumed to be X509 in PEM format.
    pub fn build_from_encrypted_input(
        application_id: &String,
        application_name: &String,
        vendor: &String,
        encrypted_payload: &mut Vec<u8>,
        nonce: &[u8],
        tag: &[u8],
        digest: &[u8],
        signature: &mut Vec<u8>,
        cert: &[u8],
    ) -> ConfidentialPackage {
        let mut package = ConfidentialPackage::new(application_id, application_name, vendor);
        package.encrypted_payload.append(encrypted_payload);
        package.encryption_key_strength = 256;
        package.encryption_key_name = application_id.clone();
        package.nonce.extend_from_slice(nonce);
        package.tag.extend_from_slice(tag);
        package.digest.extend_from_slice(digest);
        package.signature.append(signature);
        package.signature_key_strength = 2048;
        package.cert.extend_from_slice(cert);
        package
    }

    /// Populates the model from the package frame, guided by the directives in the manifest.
    pub fn build_from_frame_and_manifest(
        file: &mut File,
        frame: &Frame,
        manifest: &Manifest,
    ) -> Result<ConfidentialPackage> {
        let mut package =
            ConfidentialPackage::new(&manifest.cp_id, &manifest.cp_name, &manifest.cp_vendor);

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
    pub fn install_to(&self, cpm: &ConfidentialPackageManager) -> Result<()> {
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

    /// Forms the complete manifest document from the modelled content. This function is used when
    /// writing new packages out to disk, having built the data model from its various component parts
    /// internally.
    pub fn get_manifest(&self) -> Manifest {
        Manifest {
            cp_id: self.application_id.clone(),
            cp_name: self.application_name.clone(),
            cp_vendor: self.vendor.clone(),
            payload: Payload {
                data: 0,
                // Hard-coded target for now.
                target: Target {
                    arch: String::from("aarch64"),
                    os: String::from("OP-TEE"),
                },
                // Hard-coded dummy version data for now.
                ver: Version {
                    maj: 1,
                    min: 0,
                    rev: 0,
                    date: chrono::Utc::now().to_string(),
                },
                enc: EncryptionScheme::AesGcm {
                    key_name: String::from(self.application_id.clone()),
                    key_strength: 256,
                    nonce: 1,
                    tag: 2,
                },
                dig: DigestScheme::Sha256 { data: 3 },
                sig: SigningScheme::RsaPkcs1v15 {
                    key_strength: 2048,
                    data: 4,
                },
                cert: CertificationScheme::EmbeddedX509Pem { data: 5 },
            },
            package: Package {
                map: vec![0, 1, 2, 3, 4, 5, 6],
                dig: DigestScheme::None,
                sig: SigningScheme::None,
                cert: CertificationScheme::None,
            },
        }
    }

    /// Outputs the entire Confidential Package file to the given write stream.
    pub fn write_to_stream<S: Write>(&self, stream: &mut S) -> Result<()> {
        // Derive the manifest stream
        let manifest = self.get_manifest();
        let manifest_string = serde_json::to_string(&manifest)?;
        let manifest_bytes = manifest_string.as_bytes();

        // Write the fixed header
        stream.write_all(&MAGIC.to_le_bytes())?; // Magic number
        stream.write_all(&1u16.to_le_bytes())?; // Version
        stream.write_all(&0u16.to_le_bytes())?; // Flag (unused)
        stream.write_all(&7u16.to_le_bytes())?; // Number of streams (data, nonce, tag, digest, signature, cert, manifest)
        stream.write_all(&6u16.to_le_bytes())?; // 0-based index of the manifest stream - the final stream
        stream.write_all(&1u16.to_le_bytes())?; // Manifest "type" (currently not used, but designed for flexibility)
        stream.write_all(&1u16.to_le_bytes())?; // Manifest version

        // Write the stream table
        let mut cursor: u64 = 0;
        stream.write_all(&cursor.to_le_bytes())?;
        stream.write_all(&(self.encrypted_payload.len() as u64).to_le_bytes())?;
        cursor += self.encrypted_payload.len() as u64;
        stream.write_all(&cursor.to_le_bytes())?;
        stream.write_all(&(self.nonce.len() as u64).to_le_bytes())?;
        cursor += self.nonce.len() as u64;
        stream.write_all(&cursor.to_le_bytes())?;
        stream.write_all(&(self.tag.len() as u64).to_le_bytes())?;
        cursor += self.tag.len() as u64;
        stream.write_all(&cursor.to_le_bytes())?;
        stream.write_all(&(self.digest.len() as u64).to_le_bytes())?;
        cursor += self.digest.len() as u64;
        stream.write_all(&cursor.to_le_bytes())?;
        stream.write_all(&(self.signature.len() as u64).to_le_bytes())?;
        cursor += self.signature.len() as u64;
        stream.write_all(&cursor.to_le_bytes())?;
        stream.write_all(&(self.cert.len() as u64).to_le_bytes())?;
        cursor += self.cert.len() as u64;
        stream.write_all(&cursor.to_le_bytes())?;
        stream.write_all(&(manifest_bytes.len() as u64).to_le_bytes())?;

        // Write the streams
        stream.write_all(&self.encrypted_payload)?;
        stream.write_all(&self.nonce)?;
        stream.write_all(&self.tag)?;
        stream.write_all(&self.digest)?;
        stream.write_all(&self.signature)?;
        stream.write_all(&self.cert)?;
        stream.write_all(&manifest_bytes)?;

        Ok(())
    }
}
