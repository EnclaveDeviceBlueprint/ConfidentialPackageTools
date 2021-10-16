// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module contains the functions for calling the Confidential Package Manager (CPM)
//! on the local system.
//!
//! These functions wrap the FFI function definitions from the `cpk-sys` crate, which is a
//! dependency.
//!
//! The `cpk-sys` crate can be used either to talk to a CPM that is running within a secure
//! enclave in a production system, or to talk to a simulated CPM that is running as ordinary
//! user space software for dev/test environments.

#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    trivial_casts,
    clippy::all
)]

use cpk_sys::{
    ecall_add_application_data, ecall_begin_application_deployment,
    ecall_end_application_deployment, ecall_export_device_public_key,
    ecall_get_device_public_key_data_size, ecall_initialize_decryption_aes_gcm,
    ecall_install_application_key, ecall_is_operation_supported, ecall_ping,
    ecall_verify_application_sha256_rsa_pkcs1_v15,
    oe_create_ConfidentialPackageSpecification_enclave, oe_enclave_t,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P0,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P1,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P2,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P3,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P4,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P5,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P6,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P7,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P8,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P9,
    optee_ConfidentialPackageManagerUUID_CPM_UUID_P10,
};

use std::ffi::CString;
use thiserror::Error;

// TODO: These are not good error definitions, because they just correspond to the operations in which
// they occur, so basically don't tell us anything about the failure that caller doesn't already know.
#[derive(Error, Debug)]
pub enum CpmError {
    #[error("Failed to ping the CPM.")]
    Ping,

    #[error("Failed to determine support for an operation.")]
    IsOperationSupported,

    #[error("Failed to get device public key length.")]
    PublicKeyLength,

    #[error("Failed to get device public key data.")]
    PublicKeyData,

    #[error("Failed to install application key.")]
    InstallApplicationKey,

    #[error("Failed to start deployment session.")]
    BeginApplicationDeployment,

    #[error("Failed to initialize AES GCM decryption.")]
    InitializeAesGcmDecryption,

    #[error("Failed to add application data.")]
    AddApplicationData,

    #[error("Failed to verify the application signature and digest.")]
    VerifySha256Pkcs1v15,

    #[error("Failed to end deployment session.")]
    EndApplicationDeployment,
}

/// Represents a connection to the Confidential Package Manager running in a secure enclave.
pub struct ConfidentialPackageManager {
    enclave: *mut oe_enclave_t,
}

impl ConfidentialPackageManager {
    pub fn new() -> ConfidentialPackageManager {
        let mut enclave_ptr: *mut oe_enclave_t = std::ptr::null_mut();

        unsafe {
            // Assemble the UUD from the constants in the Specification
            let UUID = format!("{:8X}-{:4X}-{:4X}-{:4X}-{:2X}{:2X}{:2X}{:2X}{:2X}{:2X}{:2X}", 
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P0,
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P1,
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P2,
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P3,
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P4,
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P5,
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P6,
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P7,
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P8,
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P9,
                optee_ConfidentialPackageManagerUUID_CPM_UUID_P10,
                );

            let c_str = CString::new(UUID).unwrap();
            let ptr = c_str.into_raw();

            let _oe_result = oe_create_ConfidentialPackageSpecification_enclave(
                ptr,
                1,  //OE_ENCLAVE_TYPE_AUTO = 1,
                0,  // flags
                std::ptr::null_mut(),
                0,
                &mut enclave_ptr,
            );
        };

        // TODO - we are not handling failure here. Probably need to return Result().
        ConfidentialPackageManager {
            enclave: enclave_ptr,
        }
    }

    pub fn ping(&self) -> Result<u32, CpmError> {
        let version = unsafe {
            let mut retval: ::std::os::raw::c_int = 0;
            let mut contract_version: ::std::os::raw::c_uint = 0;

            let oe_result = ecall_ping(self.enclave, &mut retval, &mut contract_version);

            if (retval != 0) || (oe_result != 0) {
                return Err(CpmError::Ping);
            }

            contract_version as u32
        };

        Ok(version)
    }

    pub fn is_operation_supported(&self, operation_name: &String) -> Result<bool, CpmError> {
        let operation_name_clone = operation_name.clone();
        let c_str = CString::new(operation_name_clone).unwrap();
        let ptr = c_str.into_raw();
        let mut supported: bool = false;

        unsafe {
            let mut retval: ::std::os::raw::c_int = 0;

            let oe_result =
                ecall_is_operation_supported(self.enclave, &mut retval, ptr, &mut supported);

            let _ = CString::from_raw(ptr);
            if (retval != 0) || (oe_result != 0) {
                return Err(CpmError::IsOperationSupported);
            }
        }

        Ok(supported)
    }

    pub fn get_device_public_key(&self) -> Result<Vec<u8>, CpmError> {
        let buffer_size: usize = unsafe {
            let mut retval: ::std::os::raw::c_int = 0;
            let mut data_size: ::std::os::raw::c_uint = 0;

            let oe_result =
                ecall_get_device_public_key_data_size(self.enclave, &mut retval, &mut data_size);

            if (retval != 0) || (oe_result != 0) {
                return Err(CpmError::PublicKeyLength);
            }

            data_size as usize
        };

        let mut key: Vec<u8> = Vec::with_capacity(buffer_size);

        key.resize(buffer_size, 0);

        unsafe {
            let mut retval: ::std::os::raw::c_int = 0;

            let oe_result = ecall_export_device_public_key(
                self.enclave,
                &mut retval,
                key.as_mut_ptr(),
                buffer_size as ::std::os::raw::c_uint,
            );

            if (retval != 0) || (oe_result != 0) {
                return Err(CpmError::PublicKeyData);
            }
        }

        Ok(key)
    }

    pub fn install_application_key(
        &self,
        application_id: &String,
        wrapped_key_data: &Vec<u8>,
    ) -> Result<(), CpmError> {
        let application_id_clone = application_id.clone();
        let mut wrapped_key_clone = wrapped_key_data.clone();
        let c_str = CString::new(application_id_clone).unwrap();
        let ptr = c_str.into_raw();

        unsafe {
            let mut retval: ::std::os::raw::c_int = 0;

            let oe_result = ecall_install_application_key(
                self.enclave,
                &mut retval,
                ptr,
                wrapped_key_clone.as_mut_ptr(),
                wrapped_key_clone.len() as ::std::os::raw::c_uint,
            );

            let _ = CString::from_raw(ptr);

            if (retval != 0) || (oe_result != 0) {
                return Err(CpmError::InstallApplicationKey);
            }
        }

        Ok(())
    }

    pub fn begin_application_deployment(
        &self,
        application_id: &String,
        total_data_size: u64,
    ) -> Result<(), CpmError> {
        let application_id_clone = application_id.clone();
        let c_str = CString::new(application_id_clone).unwrap();
        let ptr = c_str.into_raw();

        unsafe {
            let mut retval: ::std::os::raw::c_int = 0;

            let oe_result = ecall_begin_application_deployment(
                self.enclave,
                &mut retval,
                ptr,
                total_data_size as ::std::os::raw::c_ulong,
            );

            let _ = CString::from_raw(ptr);
            if (retval != 0) || (oe_result != 0) {
                return Err(CpmError::BeginApplicationDeployment);
            }
        }

        Ok(())
    }

    pub fn initialize_decryption_aes_gcm(
        &self,
        application_id: &String,
        key_strength: u32,
        iv: &Vec<u8>,
        tag: &Vec<u8>,
    ) -> Result<(), CpmError> {
        let application_id_clone = application_id.clone();
        let mut iv_clone = iv.clone();
        let mut tag_clone = tag.clone();
        let c_str = CString::new(application_id_clone).unwrap();
        let ptr = c_str.into_raw();

        unsafe {
            let mut retval: ::std::os::raw::c_int = 0;

            let oe_result = ecall_initialize_decryption_aes_gcm(
                self.enclave,
                &mut retval,
                ptr,
                key_strength as ::std::os::raw::c_uint,
                iv_clone.as_mut_ptr(),
                iv_clone.len() as ::std::os::raw::c_uint,
                tag_clone.as_mut_ptr(),
                tag_clone.len() as ::std::os::raw::c_uint,
            );

            let _ = CString::from_raw(ptr);

            if (retval != 0) || (oe_result != 0) {
                return Err(CpmError::InitializeAesGcmDecryption);
            }
        }

        Ok(())
    }

    pub fn add_application_data(
        &self,
        application_id: &String,
        application_data: &Vec<u8>,
    ) -> Result<(), CpmError> {
        let application_id_clone = application_id.clone();
        let mut application_data_clone = application_data.clone();
        let c_str = CString::new(application_id_clone).unwrap();
        let ptr = c_str.into_raw();

        unsafe {
            let mut retval: ::std::os::raw::c_int = 0;

            let oe_result = ecall_add_application_data(
                self.enclave,
                &mut retval,
                ptr,
                application_data_clone.as_mut_ptr(),
                application_data_clone.len() as ::std::os::raw::c_uint,
            );

            let _ = CString::from_raw(ptr);

            if (retval != 0) || (oe_result != 0) {
                return Err(CpmError::AddApplicationData);
            }
        }

        Ok(())
    }

    pub fn verify_application_sha256_rsa_pkcs1_v15(
        &self,
        application_id: &String,
        key_strength: u32,
        digest: &Vec<u8>,
        signature: &Vec<u8>,
        public_key: &Vec<u8>,
    ) -> Result<(bool, bool), CpmError> {
        let application_id_clone = application_id.clone();
        let mut digest_clone = digest.clone();
        let mut signature_clone = signature.clone();
        let mut public_key_clone = public_key.clone();
        let c_str = CString::new(application_id_clone).unwrap();
        let ptr = c_str.into_raw();
        let mut dig_result = false;
        let mut sig_result = false;

        unsafe {
            let mut retval: ::std::os::raw::c_int = 0;

            let oe_result = ecall_verify_application_sha256_rsa_pkcs1_v15(
                self.enclave,
                &mut retval,
                ptr,
                key_strength as ::std::os::raw::c_uint,
                digest_clone.as_mut_ptr(),
                digest_clone.len() as ::std::os::raw::c_uint,
                signature_clone.as_mut_ptr(),
                signature_clone.len() as ::std::os::raw::c_uint,
                public_key_clone.as_mut_ptr(),
                public_key_clone.len() as ::std::os::raw::c_uint,
                &mut dig_result,
                &mut sig_result,
            );

            let _ = CString::from_raw(ptr);

            if (retval != 0) || (oe_result != 0) {
                return Err(CpmError::VerifySha256Pkcs1v15);
            }
        }

        Ok((dig_result, sig_result))
    }

    pub fn end_application_deployment(&self, application_id: &String) -> Result<(), CpmError> {
        let application_id_clone = application_id.clone();
        let c_str = CString::new(application_id_clone).unwrap();
        let ptr = c_str.into_raw();

        unsafe {
            let mut retval: ::std::os::raw::c_int = 0;

            let oe_result = ecall_end_application_deployment(self.enclave, &mut retval, ptr);

            let _ = CString::from_raw(ptr);
            if (retval != 0) || (oe_result != 0) {
                return Err(CpmError::EndApplicationDeployment);
            }
        }

        Ok(())
    }
}
