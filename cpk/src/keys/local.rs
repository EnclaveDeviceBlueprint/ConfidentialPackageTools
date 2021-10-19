// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements some of the key sharing protocols in terms of keys that are simply held in local
//! process memory. These might be especially convenient for testing environments.

use super::{EncryptionKeyExposure, Result, WrappingKeySource};

use pkcs1::ToRsaPublicKey;
use rand::rngs::OsRng;
use rsa::{PaddingScheme, RsaPrivateKey as RsaPriv, RsaPublicKey as RsaPub};

/// This structure implements an ephemeral RSA 2048-bit key pair in local process memory.
pub struct LocalMemoryKeyPair {
    private_key: RsaPriv,
    public_key: RsaPub,
}

impl LocalMemoryKeyPair {
    /// Create a default RSA 2048-bit random key pair in local memory.
    ///
    /// Local key pairs should only
    /// be used in dev/test environments, because the private part of the key pair is stored in the
    /// process memory, and the public part is not subject to any form of certification, making it
    /// impossible for the key owner to judge whether it is safe to wrap a secret key with this
    /// public key.
    pub fn default() -> LocalMemoryKeyPair {
        let bits = 2048;
        let mut rng = OsRng;
        let private_key = RsaPriv::new(&mut rng, bits).unwrap();
        let public_key = RsaPub::from(&private_key);
        LocalMemoryKeyPair {
            private_key: private_key,
            public_key: public_key,
        }
    }
}

impl WrappingKeySource for LocalMemoryKeyPair {
    fn get_public(&self) -> Result<Vec<u8>> {
        let public_key_document = self.public_key.to_pkcs1_der()?;
        let public_key_bytes = public_key_document.as_der();
        Ok(public_key_bytes.to_vec())
    }
}

impl EncryptionKeyExposure for LocalMemoryKeyPair {
    fn expose(&self, wrapped: &Vec<u8>) -> Result<Vec<u8>> {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let unwrapped_bytes = self.private_key.decrypt(padding, &wrapped)?;
        Ok(unwrapped_bytes)
    }
}
