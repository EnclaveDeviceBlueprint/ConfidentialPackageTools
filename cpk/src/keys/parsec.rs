// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements some of the key sharing protocols in terms of
//! [Parsec](https://parsec.community). Parsec provides platform-agnostic interfaces to
//! keys that are stored in hardware. Parsec can be a source of wrapping keys, as well as
//! signing keys.

use super::{EncryptionKeyExposure, Result, WrappingKeySource};

use parsec_client::core::interface::operations::psa_algorithm::AsymmetricEncryption;
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, Lifetime, Policy, Type, UsageFlags,
};
use parsec_client::BasicClient;

/// Implements a wrapping key pair using a locally-available Parsec service.
///
/// The key is referenced by name, and can either be a pre-provisioned key that already exists in
/// Parsec, or it can be generated on demand (in which case a 2048-bit RSA key pair will be used).
/// Pre-provisioned keys are also assumed to be RSA key pairs adopting the PKCS#1v1.5 padding
/// mechanism.
///
/// Keys that are provisioned on demand are not deleted. The expected pattern for provision-on-demand
/// would be to create the key on first use on any given system, and then re-use the key.
pub struct ParsecKeyPair {
    auth_name: String,
    key_pair_name: String,
    generate_on_demand: bool,
}

impl ParsecKeyPair {
    /// Create a Parsec key pair with explicit auth name, key pair name and provision-on-demand setting.
    ///
    /// The auth name is the client application name that will be sent to the Parsec service if it is
    /// using its direct authentication method. Most instances of the Parsec service are configured with
    /// other authentication mechanisms, so this string is only ever used in fall-back situations.
    ///
    /// The key pair name is the actual name of the key pair that will be passed into Parsec for either
    /// locating the existing key or generating the on-demand key.
    ///
    /// If `generate_on_demand` is `false` and the key of the given name does not exist, the wrapping and
    /// decryption functions will error.
    ///
    /// This function only generates the structure. It does not actually call Parsec to either locate
    /// or generate the key pair itself. This happens when the key pair is used.
    pub fn new(
        auth_name: String,
        key_pair_name: String,
        generate_on_demand: bool,
    ) -> ParsecKeyPair {
        ParsecKeyPair {
            auth_name: auth_name,
            key_pair_name: key_pair_name,
            generate_on_demand: generate_on_demand,
        }
    }

    /// Create a Parsec key pair with default settings, using `cpk` as the auth name, and
    /// `cpk_rsa_2048_keypair` as the key pair name with on-demand provisioning enabled.
    ///
    /// This function only generates the structure. It does not actually call Parsec to either locate
    /// or generate the key pair itself. This happens when the key pair is used.
    pub fn default() -> ParsecKeyPair {
        ParsecKeyPair::new(
            String::from("cpk"),
            String::from("cpk_rsa_2048_keypair"),
            true,
        )
    }
}

impl WrappingKeySource for ParsecKeyPair {
    fn get_public(&self) -> Result<Vec<u8>> {
        let basic_client = BasicClient::new(Some(self.auth_name.clone()))?;

        let keys = basic_client.list_keys()?;

        // See if Parsec has the key already.
        let existing_key = keys.iter().find(|k| k.name == self.key_pair_name);

        // If we didn't find the key, and we are configured to generate on demand, then generate the key
        // pair now.
        if existing_key == None && self.generate_on_demand {
            let attributes = Attributes {
                lifetime: Lifetime::Persistent,
                key_type: Type::RsaKeyPair,
                bits: 2048,
                policy: Policy {
                    usage_flags: UsageFlags {
                        encrypt: true,
                        decrypt: true,
                        ..Default::default()
                    },
                    permitted_algorithms: AsymmetricEncryption::RsaPkcs1v15Crypt.into(),
                },
            };

            basic_client.psa_generate_key(self.key_pair_name.clone(), attributes)?;
        }

        // This will (intentionally) fail if the key does not exist, and we didn't elect to
        // generate it on demand.
        let public_key_bytes = basic_client.psa_export_public_key(self.key_pair_name.clone())?;

        Ok(public_key_bytes)
    }
}

impl EncryptionKeyExposure for ParsecKeyPair {
    fn expose(&self, wrapped: &Vec<u8>) -> Result<Vec<u8>> {
        let basic_client = BasicClient::new(Some(self.auth_name.clone()))?;
        let unwrapped_bytes = basic_client.psa_asymmetric_decrypt(
            self.key_pair_name.clone(),
            AsymmetricEncryption::RsaPkcs1v15Crypt,
            &wrapped,
            None,
        )?;
        Ok(unwrapped_bytes)
    }
}
