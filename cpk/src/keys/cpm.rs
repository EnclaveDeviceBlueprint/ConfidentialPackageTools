// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements key sharing protocols in terms of the Confidential Package Manager (CPM),
//! which is both a source for wrapping keys and a destination for encryption keys (although it is
//! never a source of encryption keys).

use crate::cpm::ConfidentialPackageManager;
use super::{EncryptionKeyDestination, WrappingKeySource, Result};
use super::error::KeyError;

impl EncryptionKeyDestination for ConfidentialPackageManager {
    fn unwrap(&self, key_id: &String, wrapped: &Vec<u8>) -> Result<()> {
        match self.install_application_key(key_id, wrapped) {
            Ok(()) => Ok(()),
            Err(e) => Err(KeyError::CpmKeyManagementError(e)),
        }
    }
}

impl WrappingKeySource for ConfidentialPackageManager {
    fn get_public(&self) -> Result<Vec<u8>> {
        match self.get_device_public_key() {
            Ok(k) => Ok(k),
            Err(e) => Err(KeyError::CpmKeyManagementError(e)),
        }
    }
}
