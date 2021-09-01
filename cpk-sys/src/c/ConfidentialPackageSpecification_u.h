// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

/*
 *  This file is auto generated by oeedger8r. DO NOT EDIT.
 *  (Actually, this is a manually-modified adjustment to the oeedger8r output, allowing for bindgen and
 *  compilation under simulated conditions without a TEE or OE dev environment).
 */
#ifndef EDGER8R_CONFIDENTIALPACKAGESPECIFICATION_U_H
#define EDGER8R_CONFIDENTIALPACKAGESPECIFICATION_U_H

#include "ConfidentialPackageSpecification_args.h"

/* MANUAL MODIFICATION: Include platform int definitions. */
#include <stdint.h>

/* MANUAL MODIFICATION: Hacky typedefs to avoid depending on OE */
typedef int oe_enclave_type_t;
typedef void oe_enclave_setting_t;
typedef void oe_enclave_t;
typedef int oe_result_t;
typedef int bool;

oe_result_t oe_create_ConfidentialPackageSpecification_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const oe_enclave_setting_t* settings,
    uint32_t setting_count,
    oe_enclave_t** enclave);

/**** ECALL prototypes. ****/
oe_result_t ecall_ping(
    oe_enclave_t* enclave,
    int* _retval,
    unsigned int* supported_contract_version);

oe_result_t ecall_is_operation_supported(
    oe_enclave_t* enclave,
    int* _retval,
    char* operation_name,
    bool* is_supported);

oe_result_t ecall_get_device_public_key_data_size(
    oe_enclave_t* enclave,
    int* _retval,
    unsigned int* data_size);

oe_result_t ecall_export_device_public_key(
    oe_enclave_t* enclave,
    int* _retval,
    unsigned char* data,
    unsigned int data_size);

oe_result_t ecall_install_application_key(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id,
    unsigned char* data,
    unsigned int data_size);

oe_result_t ecall_begin_application_deployment(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id,
    unsigned long int total_data_size);

oe_result_t ecall_initialize_decryption_aes_gcm(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id,
    unsigned int key_strength,
    unsigned char* iv,
    unsigned int iv_size,
    unsigned char* tag,
    unsigned int tag_size);

oe_result_t ecall_add_application_data(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id,
    unsigned char* data,
    unsigned int data_size);

oe_result_t ecall_verify_application_sha256_rsa_pkcs1_v15(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id,
    unsigned int key_strength,
    unsigned char* digest,
    unsigned int digest_size,
    unsigned char* signature,
    unsigned int signature_size,
    unsigned char* public_key,
    unsigned int public_key_size,
    bool* digest_match,
    bool* signature_match);

oe_result_t ecall_end_application_deployment(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id);

/**** OCALL prototypes. ****/
int ocall_log(char* msg);


#endif // EDGER8R_CONFIDENTIALPACKAGESPECIFICATION_U_H
