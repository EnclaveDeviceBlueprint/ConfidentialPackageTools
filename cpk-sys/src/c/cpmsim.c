// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

/*
 * cpmsim.c
 *
 * Normal-world simulator for Confidential Package Manager, allowing for tests to be written without any dependency
 * on a TEE or OpenEnclave, but still approximately honouring the expected behaviour of the CPM.
 * 
 * The simulation is quite crude, but functional. Key pairs and cryptographic capabilities are genuine, and implemented
 * using Mbed TLS via the PSA Crypto API. There are restrictions, though. The simulator can only simulate the installation
 * of a single application as a single block of data, and it is not thread-safe.
 * 
 * The oe_enclave_t* pointer is always NULL and ignored. There is no actual oe_enclave_t structure defined in
 * the simulator, because the simulator avoids all dependencies on OE. The type is aliased to void.
 */

// Include the actual OE contract stub so that our simulation is of precisely the correct interface.
#include "ConfidentialPackageSpecification_u.h"

// Functionality needed by the simulator.
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

#define UNUSED(x) (void)(x)

#define KEY_STRENGTH 2048

static mbedtls_svc_key_id_t key_pair_id = 72; /* Arbitrary fixed id to use for the RSA keypair */
static mbedtls_svc_key_id_t application_key_id = 73; /* Arbitrary fixed id to use for the application key.
                                                        ASSUME: We only need one such key, because the simulator will
                                                        only support one application deployment at a time. */
static mbedtls_svc_key_id_t verification_public_key_id = 74; /* Arbitrary fixed id to use for the public key for
                                                                signature verification. Same assumption as above. */

// Boolean flag, flips to 1 as soon as we have provisioned the device keypair, so we only do that once.
static int key_generated = 0;

// This array receives the output from psa_export_public_key(), which is a DER encoding of
// the RSAPublicKey structure.
static unsigned char public_key[PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(KEY_STRENGTH)] = {0};

// This length is the length of the public key data in bytes (not to be confused with key strength)
static size_t public_key_length;

/* These store the data and size for the application key (id 73), which is injected by the host.
   The simulator only has "room" for one such key, and in PSA it will have the id 73. We can't handle
   the injection of multiple keys and installations at the same time. */
static uint8_t unwrapped_key[256] = {0};

/* This is initialized to zero, and also set back to zero when the caller finalizes the operation. */
static size_t unwrapped_key_length = 0;

// Handle up to 1Mb of encrypted application data by allocating it statically.
// (Larger sizes could be handled by malloc/free, but this is only a simulator)
#define MAX_APPLICATION_DATA (1 * 1024 * 1024)
#define MAX_TAG 256
#define MAX_NONCE 256

/* In-memory static storage for the application data. We only support one chunk, and it can't be any bigger
   than MAX_APPLICATION_DATA */
static uint8_t application_ciphertext[MAX_APPLICATION_DATA + MAX_TAG] = {0};
static size_t ciphertext_size = 0;
static uint8_t application_plaintext[MAX_APPLICATION_DATA] = {0};
static size_t plaintext_size = 0;
static uint8_t gcm_auth_tag[MAX_TAG] = {0};
static size_t gcm_auth_tag_size = 0;
static uint8_t gcm_nonce[MAX_NONCE] = {0};
static size_t gcm_nonce_size = 0;

static psa_status_t ensure_key()
{
    if (key_generated == 0)
    {
        psa_status_t status;
        psa_key_handle_t key_pair_handle;
        psa_key_attributes_t key_pair_attributes = PSA_KEY_ATTRIBUTES_INIT;

        status = psa_crypto_init();

        if (status != PSA_SUCCESS)
        {
            return status;
        }

        psa_set_key_id(&key_pair_attributes, key_pair_id);
        psa_set_key_lifetime(&key_pair_attributes, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_usage_flags(&key_pair_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&key_pair_attributes, PSA_ALG_RSA_PKCS1V15_CRYPT);
        psa_set_key_type(&key_pair_attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&key_pair_attributes, KEY_STRENGTH);

        status = psa_generate_key(&key_pair_attributes, &key_pair_handle);

        if (status == PSA_ERROR_ALREADY_EXISTS)
        {
            // Keys are persistent, so we might already have the key from a previous simulator run.
            // This is okay, but we need to initialize the handle to be the same as the id
            key_pair_handle = key_pair_id;
            status = PSA_SUCCESS;
        }

        if (status != PSA_SUCCESS)
        {
            return status;
        }

        // Eagerly export the public key and store it, so that we can easily just memcpy it to the caller
        // on demand.
        status = psa_export_public_key(key_pair_handle,
                                       public_key,
                                       sizeof(public_key),
                                       &public_key_length);

        if (status != PSA_SUCCESS)
        {
            return status;
        }

        key_generated = 1;
        return status;
    }
    else
    {
        /* Already provisioned. Nothing to do. */
        return PSA_SUCCESS;
    }
}

oe_result_t oe_create_ConfidentialPackageSpecification_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const oe_enclave_setting_t* settings,
    uint32_t setting_count,
    oe_enclave_t** enclave)
{
    UNUSED(path);
    UNUSED(type);
    UNUSED(flags);
    UNUSED(settings);
    UNUSED(setting_count);
    *enclave = NULL;
    return 0;
}

/**** ECALL prototypes. ****/
oe_result_t ecall_ping(
    oe_enclave_t* enclave,
    int* _retval,
    unsigned int* supported_contract_version)
{
    UNUSED(enclave);
    *_retval = 0;
    *supported_contract_version = 1;
    return 0;
}

oe_result_t ecall_is_operation_supported(
    oe_enclave_t* enclave,
    int* _retval,
    char* operation_name,
    bool* is_supported)
{
    UNUSED(enclave);
    *_retval = 0;
    *is_supported = 0;
    if (!strcmp(operation_name, "ecall_ping")
        || !strcmp(operation_name, "ecall_is_operation_supported")
        || !strcmp(operation_name, "ecall_get_device_public_key_data_size")
        || !strcmp(operation_name, "ecall_export_device_public_key")
        || !strcmp(operation_name, "ecall_install_application_key")
        || !strcmp(operation_name, "ecall_begin_application_deployment")
        || !strcmp(operation_name, "ecall_initialize_decryption_aes_gcm")
        || !strcmp(operation_name, "ecall_add_application_data")
        || !strcmp(operation_name, "ecall_verify_application_sha256_rsa_pkcs1_v15")
        || !strcmp(operation_name, "ecall_end_application_deployment"))
    {
        *is_supported = 1;
    }

    return 0;
}

oe_result_t ecall_get_device_public_key_data_size(
    oe_enclave_t* enclave,
    int* _retval,
    unsigned int* data_size)
{
    UNUSED(enclave);

    if (ensure_key() == PSA_SUCCESS)
    {
        *data_size = (unsigned int) public_key_length;
        *_retval = 0;
    }
    else
    {
        ocall_log("RSA keypair provisioning failed.");
        *_retval = 1; /* TODO: Map PSA error to REE/TEE interface code, TBD */
    }

    return 0;
}

oe_result_t ecall_export_device_public_key(
    oe_enclave_t* enclave,
    int* _retval,
    unsigned char* data,
    unsigned int data_size)
{
    UNUSED(enclave);

    if (ensure_key() == PSA_SUCCESS && data_size >= (unsigned int) public_key_length)
    {
        // We don't need to call PSA here, because we export the public key at key-generation time,
        // so just copy the data that we already have.
        memcpy(data, public_key, public_key_length);
        *_retval = 0;
    }
    else
    {
        ocall_log("RSA keypair provisioning failed.");
        *_retval = 1; /* TODO: Map PSA error to REE/TEE interface code, TBD */
    }

    return 0;
}

oe_result_t ecall_install_application_key(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id,
    unsigned char* data,
    unsigned int data_size)
{
    UNUSED(enclave);
    UNUSED(application_id);

    if (ensure_key() == PSA_SUCCESS)
    {
        psa_status_t status;
        
        /* We need to decrypt ("unwrap") the application key data first, using the private part of the RSA
           key pair. */

        status =  psa_asymmetric_decrypt(key_pair_id,
                                         PSA_ALG_RSA_PKCS1V15_CRYPT,
                                         data,
                                         (size_t) data_size,
                                         NULL,
                                         0,
                                         unwrapped_key,
                                         sizeof(unwrapped_key),
                                         &unwrapped_key_length);

        if (status != PSA_SUCCESS)
        {
            *_retval = 1; /* TODO: Map PSA error to REE/TEE interface code, TBD */
            return 0;
        }

        *_retval = 0;
    }
    else
    {
        ocall_log("RSA keypair provisioning failed.");
        *_retval = 1; /* TODO: Map PSA error to REE/TEE interface code, TBD */
    }

    return 0;
}

oe_result_t ecall_begin_application_deployment(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id,
    unsigned long int total_data_size)
{
    /* Nothing meaningful to do here in the simulator. */
    UNUSED(enclave);
    UNUSED(application_id);
    UNUSED(total_data_size);
    *_retval = 0;
    return 0;
}

oe_result_t ecall_initialize_decryption_aes_gcm(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id,
    unsigned int key_strength,
    unsigned char* iv,
    unsigned int iv_size,
    unsigned char* tag,
    unsigned int tag_size)
{
    UNUSED(enclave);
    UNUSED(application_id);

    if (unwrapped_key_length == 0)
    {
        /* We have no key to decrypt with. */
        *_retval = 1;
        return 0;
    }
    else
    {
        psa_status_t status;
        psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
        mbedtls_svc_key_id_t key_id_confirmed;

        /* Import the unwrapped key as 'application_key_id' (73), specifying AES key type and GCM
           algorithm. */
        psa_set_key_id(&key_attributes, application_key_id);
        psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&key_attributes, PSA_ALG_GCM);
        psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&key_attributes, key_strength);

        status = psa_import_key(&key_attributes,
                                unwrapped_key,
                                unwrapped_key_length,
                                &key_id_confirmed);

        if (status == PSA_ERROR_ALREADY_EXISTS)
        {
            // This might happen if a previous run failed halfway through and left the application
            // key behind. For robustness, try and delete the key and then have another go.
            (void) psa_destroy_key(application_key_id);

            status = psa_import_key(&key_attributes,
                                    unwrapped_key,
                                    unwrapped_key_length,
                                    &key_id_confirmed);
        }

        if (status != PSA_SUCCESS)
        {
            *_retval = 1;
            return 0;
        }

        if (key_id_confirmed != application_key_id)
        {
            /* Better check that PSA has adopted the correct persistent id for this key. */
            *_retval = 1;
            return 0;
        }

        if ((size_t) iv_size > MAX_NONCE || (size_t) tag_size > MAX_TAG)
        {
            /* If the nonce or tag are too big for local in-memory storage, fail. */
            *_retval = 1;
            return 0;
        }

        /* Just copy the nonce/IV and auth tag to local in-memory storage. */
        memcpy(gcm_nonce, iv, iv_size);
        gcm_nonce_size = iv_size;
        memcpy(gcm_auth_tag, tag, tag_size);
        gcm_auth_tag_size = tag_size;
    }

    return 0;
}

oe_result_t ecall_add_application_data(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id,
    unsigned char* data,
    unsigned int data_size)
{
    psa_status_t status;

    UNUSED(enclave);
    UNUSED(application_id);

    if (data_size > MAX_APPLICATION_DATA)
    {
        *_retval = 1;
        return 0;
    }

    if (gcm_auth_tag_size == 0 || gcm_nonce_size == 0)
    {
        /* We were not initialized before the application data was passed. */
        *_retval = 1;
        return 0;
    }

    if (plaintext_size != 0)
    {
        /* We were already called to decrypt. We don't expect more data. */
        *_retval = 0;
        return 0;
    }

    /* The simulator will only handle one block of application data. Just copy it to local memory. */
    memcpy(application_ciphertext, data, data_size);

    /* PSA API requires the auth tag to follow the data. */
    memcpy(application_ciphertext + data_size, gcm_auth_tag, gcm_auth_tag_size);

    /* Decrypt! */
    status = psa_aead_decrypt(application_key_id,
                              PSA_ALG_GCM,
                              gcm_nonce,
                              gcm_nonce_size,
                              NULL,
                              0,
                              application_ciphertext,
                              data_size + gcm_auth_tag_size, // The total payload is the data plus the tag.
                              application_plaintext,
                              sizeof(application_plaintext),
                              &plaintext_size);
    
    if (status != PSA_SUCCESS)
    {
        *_retval = 1;
        return 0;
    }

    *_retval = 0;
    return 0;
}

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
    bool* signature_match)
{
    UNUSED(enclave);
    UNUSED(application_id);

    *digest_match = 0;
    *signature_match = 0;

    if (plaintext_size == 0)
    {
        /* We have no decrypted application data to verify. */
        *_retval = 1;
        return 0;
    }
    else
    {
        psa_status_t status;
        psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
        mbedtls_svc_key_id_t key_id_confirmed;

        /* Check the hash first, because there's no point in checking the signature if that fails. */
        status = psa_hash_compare(PSA_ALG_SHA_256,
                                  application_plaintext,
                                  plaintext_size,
                                  digest,
                                  digest_size);

        if (status == PSA_ERROR_INVALID_SIGNATURE)
        {
            // The hash was computed, but does not match. Successful return value, but unfavourable output.
            *_retval = 0;
            return 0;
        }
        else if (status != PSA_SUCCESS)
        {
            // Some other PSA Crypto error, just fail the function.
            *_retval = 1;
            return 0;
        }

        // If we get here, the hash is valid at least.
        *digest_match = 1;

        /* Import the RSA public key so that we can do PSA operations on it. */
        psa_set_key_id(&key_attributes, verification_public_key_id);
        psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_HASH);
        psa_set_key_algorithm(&key_attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
        psa_set_key_type(&key_attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        psa_set_key_bits(&key_attributes, key_strength);

        status = psa_import_key(&key_attributes,
                                public_key,
                                public_key_size,
                                &key_id_confirmed);

        if (status != PSA_SUCCESS)
        {
            *_retval = 1;
            return 0;
        }

        if (key_id_confirmed != verification_public_key_id)
        {
            /* Better check that PSA has adopted the correct persistent id for this key. */
            *_retval = 1;
            return 0;
        }

        /* Check the signature. */
        status = psa_verify_hash(verification_public_key_id,
                                 PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
                                 digest,
                                 digest_size,
                                 signature,
                                 signature_size);

        /* Immediately remove the key again, without worrying about the status. */
        (void) psa_destroy_key(verification_public_key_id);

        if (status == PSA_ERROR_INVALID_SIGNATURE)
        {
            // The sig was computed, but does not match. Successful return value, but unfavourable output.
            *_retval = 0;
            return 0;
        }
        else if (status != PSA_SUCCESS)
        {
            // Some other PSA Crypto error, just fail the function.
            *_retval = 1;
            return 0;
        }

        /* If we get here, the signature matches. */
        *signature_match = 1;
        *_retval = 0;
    }

    return 0;
}

oe_result_t ecall_end_application_deployment(
    oe_enclave_t* enclave,
    int* _retval,
    char* application_id)
{
    UNUSED(enclave);
    UNUSED(application_id);

    /* Destroy the application key (id = 73), so that a new one can be created with the same id if we
       go around again. */
    (void) psa_destroy_key(application_key_id);

    /* Clear all per-application bits. */
    memset(application_ciphertext, 0, sizeof(application_ciphertext));
    memset(application_plaintext, 0, sizeof(application_plaintext));
    memset(gcm_nonce, 0, sizeof(gcm_nonce));
    memset(gcm_auth_tag, 0, sizeof(gcm_auth_tag));
    memset(unwrapped_key, 0, sizeof(unwrapped_key));

    unwrapped_key_length = 0;
    gcm_nonce_size = 0;
    gcm_auth_tag_size = 0;
    ciphertext_size = 0;
    plaintext_size = 0;

    *_retval = 0;
    return 0;
}

/**** OCALL prototypes. ****/
int ocall_log(char* msg)
{
    printf("OCALL_LOG MSG: %s\n", msg);
    return 0;
}
