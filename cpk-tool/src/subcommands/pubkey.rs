// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Obtains the device public key from the Confidential Package Manager on the local device
//! and writes it to the console as base64-encoding of the ASN.1 SubjectPublicKeyInfo structure.

use crate::error::Result;

use cpk::cpm::ConfidentialPackageManager;
use picky_asn1_x509::subject_public_key_info::SubjectPublicKeyInfo;
use picky_asn1_x509::RsaPublicKey;

use structopt::StructOpt;

/// Models the options required by the pubkey command.
#[derive(Debug, StructOpt)]
pub struct PubKey {}

impl PubKey {
    /// Obtains the public part of the device key pair and writes it to standard output as a
    /// SubjectPublicKeyInfo structure in base64. (This format is used by default since it is directly
    /// compatible with the format expected by key sharing mechanisms, meaning that the output of
    /// this command can be copied verbatim into any cloud-side key management function).
    pub fn run(&self) -> Result<()> {
        let cpm = ConfidentialPackageManager::new();
        let device_public = cpm.get_device_public_key()?;
        let rsa_public_key: RsaPublicKey = picky_asn1_der::from_bytes(&device_public)?;

        // The default output format for this command is SubjectPublicKeyInfo as ASN.1 DER, because this
        // format is directly compatible with cloud-side key distribution mechanisms, meaning that the
        // output of this command can be used verbatim when interacting with those functions. In the future,
        // we can introduce command-line controls to issue other formats where those are needed.
        let subject_public_key_info = SubjectPublicKeyInfo::new_rsa_key(
            rsa_public_key.modulus,
            rsa_public_key.public_exponent,
        );

        let key_info_bytes = picky_asn1_der::to_vec(&subject_public_key_info)?;

        let device_public_key_base64 = base64::encode(key_info_bytes);

        // Print just the key data with no additional verbosity. This helps scripting clients who just
        // want the data to forward somewhere for key synchronization purposes.
        println!("{}", device_public_key_base64);

        Ok(())
    }
}
