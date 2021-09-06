// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements Version 1 of the manifest JSON document.

use serde::{Deserialize, Serialize};

/// Defines the encryption scheme (algorithm and key strength) for a section of the package. Currently, only
/// AES-GCM encryption is supported for confidential packages.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionScheme {
    /// Indicates that the referred content is in plain text (non-encrypted).
    None,
    /// Indicates that the referred content is encrypted with authenticated AES in GCM mode.
    AesGcm {
        /// The name of the key, which allows for the key to be obtained through appropriate key-retrieval
        /// mechanisms where multiple keys might potentially be available. The consumer is assumed to
        /// understand how to obtain the key via a suitable mechanism. Confidential packages deliberately
        /// do not provide any further information about key retrieval.
        pub key_name: String,

        /// The strength of the AES key in bits, such as 256.
        pub key_strength: u16,

        /// Stream index to the nonce byte vector for decryption.
        pub nonce: u16,

        /// Stream index to the authentication tag to verify the decryption process.
        pub tag: u16,
    },
}

/// Defines the hashing/digest scheme for a section of the package.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestScheme {
    /// No digest scheme.
    None,

    /// Indicates use of the SHA-256 algorithm.
    Sha256 {
        /// Stream index to the byte vector containing the SHA-256 hash for the referred
        /// content.
        pub data: u16,
    },
}

/// Defines how a section of the package has been signed.
///
/// For verifying signatures, consumers should examine the [CertificationScheme] part of the
/// manifest, which defines how to obtain the corresponding public key or certificate.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningScheme {
    /// Indicates no signing scheme - the referred content is unsigned.
    None,
    /// Indicates a signature using RSA with PKCS1 v1.5 padding.
    RsaPkcs1v15 {
        /// The strength of the RSA key, in bits (typically 2048).
        pub key_strength: u16,
        /// Stream index to the vector of bytes containing the signature.
        pub data: u16,
    },
}

/// Defines how a signature can be verified using a public key or certificate.
///
/// All package sections that supply a [SigningScheme] must also supply a corresponding
/// [CertificationScheme] so that the consumer is able to verify the signature.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificationScheme {
    /// Indicates no certification scheme.
    None,

    /// Indicates that the target (the device on which the package is being installed) should already
    /// have the required certificate or public key, because it has been pre-shared by some mechanism
    /// outside of the confidential package.
    Target {
        /// The domain name of the package producer (eg. "somevendor.com"), which allows the target device
        /// to select a suitable signing certificate from its store.
        pub domain: String,
    },

    /// Indicates that the certificate can be downloaded from a URL.
    Url {
        /// The URL to obtain the certificate. It should be possible to download an X509 file by
        /// performing a direct `wget` on this location.
        pub url: String,
    },

    /// Indicates that an X509 certificate is embedded directly in this confidential package in PEM
    /// format.
    EmbeddedX509Pem {
        /// The stream index of the PEM-formatted X509 certificate within the package.
        pub data: u16,
    },

    /// Indicates that an X509 certificate is embedded directly in this confidential package as a
    /// DER encoding.
    EmbeddedX509Der {
        /// The stream index of the DER-encoded X509 certificate within the package.
        pub data: u16,
    },

    /// Indicates that a bare public key (without a certificate) is embedded directly in this confidential
    /// package in PEM format.
    EmbeddedPublicKeyPem {
        /// The stream index of the PEM-formatted public key data.
        ///
        /// Public keys are assumed to be encoded as SubjectPublicKeyInfo.
        pub data: u16,
    },

    /// Indicates that a bare public key (without a certificate) is embedded directly in this confidential
    /// package as a DER encoding.
    EmbeddedPublicKeyDer {
        /// The stream index of the DER-encoded public key data.
        ///
        /// Public keys are assumed to be encoded as SubjectPublicKeyInfo.
        pub data: u16,
    },
}

/// This structure encapsulates all versioning and build information for the confidential application payload being
/// transported in the package.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Version {
    /// The major version number.
    pub maj: u32,

    /// The minor version number.
    pub min: u32,

    /// The revision, build number or patch level.
    pub rev: u32,

    /// The date and time that the build was produced, in ISO 8601 string format.
    pub date: String,
}

/// This structure describes the payload, which is the confidential application binary itself.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Payload {
    /// Stream index to the binary data for the compiled application.
    pub data: u16,

    /// This section collects the version and revision/patch level information for the application.
    pub ver: Version,

    /// This section defines how the payload has been encrypted.
    pub enc: EncryptionScheme,

    /// This section defines the hash or digest for the payload.
    pub dig: DigestScheme,

    /// This section defines how the payload has been signed.
    pub sig: SigningScheme,

    /// This section defines how the payload signature can be verified.
    pub cert: CertificationScheme,
}

/// This structure describes the overall package, along with any additional signing or certification
/// mechanism.
/// 
/// Confidential packages allow for the possibility that the payload (application) might be signed separately
/// from the overall package, and possibly even by a different entity with a different certificate.
/// 
/// Signing details for the application payload are provided in the [Payload] section of the manifest.
/// 
/// If the whole package is signed, then this section should be used to understand how to check and
/// verify the signature.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Package {
    /// This section describes which of the package's data streams have been signed, and in what order.
    /// 
    /// Each member of this vector is a zero-based stream index, which must refer to one of the data
    /// streams (possibly including the manifest stream). The vector must not contain duplicates, but
    /// it can be in an arbitrary order. To verify the hash and signature, the consumer must process all
    /// of the bytes in all of the streams in this vector, in the order given.
    pub map: Vec<u16>,

    /// This section defines how the hash (digest) has been computed for the streams.
    pub dig: DigestScheme,

    /// This section defines how the signature has been computed for the digest.
    pub sig: SigningScheme,

    /// This section defines how the consumer can obtain the public key or certificate for verifying the
    /// package signature.
    pub cert: CertificationScheme,
}

/// The root level of the manifest document.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Root {
    /// The unique identity of this confidential package. (A UUID in string form).
    pub cp_id: String,

    /// The human-readable name of this confidential package.
    pub cp_name: String,

    /// The human-readable vendor or service provider name.
    pub cp_vendor: String,

    /// This section defines the payload, which is the confidential application itself.
    pub payload: Payload,

    /// This section provides signing details for the overall package, if the package has been signed separately
    /// from the payload.
    pub package: Package,
}
