// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements a simple file-based key source. The purpose of a file-based
//! key source is mainly to allow the tool chain to be developed and tested in the absence of
//! any cloud services or online key storage services. In production environments, this kind of
//! key source would almost certainly not be used. Instead, encryption keys would be stored
//! in a cloud vault or online HSM. This option is mainly for convenience in testing small,
//! local deployments of the tool chain and package manager.

use crate::keys::error::KeyError;

use super::{EncryptionKeySource, Result};

use serde_json::{Map, Value};

use pkcs1::FromRsaPublicKey;
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey as RsaPub};

use std::fs::File;
use std::io::BufReader;

/// This structure implements an encryption key source based on a simple file on the local
/// filesystem.
///
/// The file is assumed to be in JSON format, and is a simple hash map of key identifiers to
/// base64-encoded encryption keys.
///
/// An example file containing just a single key might look like this:
///
/// `````
/// {
///     "5d286b7e-ff68-4b4b-b7b8-05f55dbfd0c7" : "QfTjWnZr4u7x!A%D*G-KaPdRgUkXp2s5"
/// }
/// `````
///
/// File key sources are immutable. The contents need to have been created separately by an admin.
/// This tool is not able to add, remove or modify keys within the store.
pub struct FileKeySource {
    map: Map<String, Value>,
}

impl FileKeySource {
    /// Makes a [FileKeySource] from the given file path. The given path should be a path to a file
    /// that exists and can be opened on the local file system. The file needs to contain valid JSON
    /// in the format described for [FileKeySource].
    pub fn from_file_path(file_path: &String) -> Result<FileKeySource> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let root: Value = serde_json::from_reader(reader)?;
        let map: &Map<String, Value> = root.as_object().ok_or(KeyError::FileKeySourceBadFormat)?;
        let source = FileKeySource { map: map.clone() };
        Ok(source)
    }
}

impl EncryptionKeySource for FileKeySource {
    fn wrap(&self, key_id: &String, public_key: &Vec<u8>) -> Result<Vec<u8>> {
        // Get the key from the JSON map - error if not present
        let entry = self.map.get(key_id).ok_or(KeyError::KeyNotFound)?;

        // Expect a base64 string. Error if it is not a string, or can't be decoded.
        let base64: &str = entry.as_str().ok_or(KeyError::FileKeySourceBadFormat)?;
        let key = base64::decode(base64)?;

        // Now parse the given public key into an RsaPublicKey.
        let rsa_pub = RsaPub::from_pkcs1_der(public_key.as_slice())?;
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut rng = OsRng;

        // Wrap the encryption key and return the wrapped bytes.
        let wrapped = rsa_pub.encrypt(&mut rng, padding, &key)?;
        Ok(wrapped)
    }
}
