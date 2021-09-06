// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements key sharing protocols in terms of HTTP/REST contracts, enabling keys to
//! be retrieved from cloud services that expose a suitable wrapping API.
//!
//! Currently, the only wrapping API that is supported is the one defined as part of the
//! Confidential Packaging Specification. But other styles of wrapping could be implemented and contributed
//! to the project.

use super::{EncryptionKeySource, Result};

use serde::{Deserialize, Serialize};

use picky_asn1_x509::subject_public_key_info::SubjectPublicKeyInfo;
use picky_asn1_x509::RsaPublicKey;

/// Represents the JSON request body that will be posted to the web contract.
#[derive(Debug, Serialize, Deserialize)]
struct KeyWrapRequest {
    /// The name of the key that the client is asking to wrap.
    key_name: String,

    /// The client's public key for wrapping. This must be a base64 encoding of a
    /// DER `SubjectPublicKeyInfo` structure.
    client_public_key: String,
}

/// Represents the JSON response body that is returned by the web contract in the
/// successful case.
#[derive(Debug, Serialize, Deserialize)]
struct KeyWrapResponse {
    wrapped_key: String,
}

/// This structure implements an encryption key source based on an HTTP web contract that is defined
/// as part of the Confidential Package Specification.
pub struct WebContractKeySource {
    /// The endpoint URI where the contract is implemented in the cloud.
    endpoint_uri: String,
}

impl EncryptionKeySource for WebContractKeySource {
    fn wrap(&self, key_id: &String, public_key: &Vec<u8>) -> Result<Vec<u8>> {
        let rsa_public_key: RsaPublicKey = picky_asn1_der::from_bytes(&public_key)?;

        // The Http contract expects SubjectPublicKeyInfo not RSAPublicKey, so do the conversion
        // before calling.
        let subject_public_key_info = SubjectPublicKeyInfo::new_rsa_key(
            rsa_public_key.modulus,
            rsa_public_key.public_exponent,
        );

        let key_info_bytes = picky_asn1_der::to_vec(&subject_public_key_info)?;

        let wrapping_key_base64 = base64::encode(key_info_bytes);

        // Create the request body that we will POST to the endpoint.
        let key_wrap_request = KeyWrapRequest {
            key_name: key_id.clone(),
            client_public_key: wrapping_key_base64,
        };

        let res = reqwest::blocking::Client::new()
            .post(&self.endpoint_uri)
            .json(&key_wrap_request)
            .send()?;

        // TODO: Assuming a successful response here! Need to handle errors from the web
        // contract.
        let key_wrap_response = res.json::<KeyWrapResponse>()?;
        let wrapped_bytes = base64::decode(key_wrap_response.wrapped_key)?;
        Ok(wrapped_bytes)
    }
}
