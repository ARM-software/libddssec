/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_ih_privkey.h>
#include <dsec_ta_ih.h>
#include <dsec_ta_manage_object.h>
#include <dsec_macros.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#define SHA256_DATA_SIZE (32U)

/*
 * Callback function to generate random numbers for mbedTLS using TEE function.
 */
static int optee_ctr_drbg_random(void* p_rng,
                                 unsigned char* output,
                                 size_t output_len)
{
    /*
     * Unused pseudo random generator context as we use TEE_GenerateRandom for
     * the generation.
     */
    DSEC_UNUSED(p_rng);
    int result = 0;

    if (output == NULL) {
        result = 1;
    }

    TEE_GenerateRandom(output, output_len);
    return result;
}

/*
 * This function checks the given inputs to make sure they are valid and can be
 * used as inputs for privkey_sign(...)
 */
static TEE_Result privkey_sign_check_input(
    const unsigned char* input,
    size_t input_size,
    const unsigned char* signature,
    size_t signature_size)
{

    TEE_Result result = 0;
    const mbedtls_ecp_curve_info* curve_info = NULL;

    if ((input != NULL) &&
        (input_size != 0) &&
        (signature != NULL) &&
        (signature_size != 0)) {

        curve_info =
            mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);

        if (curve_info != NULL) {
            unsigned int bitlength = curve_info->bit_size;
            size_t max_signature_size = 2 * (bitlength / 8) + 9;

            /*
             * Make sure that the output buffer for the signature is big
             * enough to contain the actual signature produced
             */
            if (max_signature_size <= signature_size) {
                result = TEE_SUCCESS;
            } else {
                EMSG("Signature buffer is too small.\n");
                result = TEE_ERROR_SHORT_BUFFER;
            }
        } else {
            EMSG("Could not retrieve information about ECP.\n");
            result = TEE_ERROR_BAD_FORMAT;
        }

    } else {
        EMSG("Input parameters are invalid (NULL or 0).\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

/*
 * Sign a given buffer using the private key.
 * Note: This function is not making any checks on its input and assumes that
 *     all its arguments are valid. This function should be called after
 *     privkey_sign_check_input(...) and after making sure mbedtls_ecp_keypair*
 *     is not NULL.
 */
static TEE_Result privkey_sign(const mbedtls_ecp_keypair* ecp_privkey,
                               const unsigned char* input,
                               size_t input_size,
                               unsigned char* signature,
                               size_t* signature_size)
{
    TEE_Result result = 0;
    int result_mbedtls = 0;

    mbedtls_ecdsa_context ecdsa_privkey;
    /* Contains the SHA256 of the incoming buffer to be signed */
    unsigned char data_sha256[SHA256_DATA_SIZE] = {0};
    size_t output_signature_size = 0;

    mbedtls_ecdsa_init(&ecdsa_privkey);
    result_mbedtls = mbedtls_ecdsa_from_keypair(&ecdsa_privkey, ecp_privkey);

    if (result_mbedtls == 0) {
        /* Generate a SHA256 of the message */
        mbedtls_sha256(input, input_size, data_sha256, 0 /* is224 */);

        result_mbedtls = mbedtls_ecdsa_write_signature(&ecdsa_privkey,
                                                       MBEDTLS_MD_SHA256,
                                                       data_sha256,
                                                       SHA256_DATA_SIZE,
                                                       signature,
                                                       &output_signature_size,
                                                       optee_ctr_drbg_random,
                                                       NULL /* p_rng */);

        if (result_mbedtls == 0) {
            result = TEE_SUCCESS;
            *signature_size = output_signature_size;
        } else {
            EMSG("Could not generate signature: 0x%x.\n", result_mbedtls);
            result = TEE_ERROR_SECURITY;
            *signature_size = 0;
        }

        mbedtls_ecdsa_free(&ecdsa_privkey);

    } else {
        EMSG("Could not extract private key: 0x%x.\n", result_mbedtls);
        result = TEE_ERROR_BAD_FORMAT;
    }

    return result;
}

/*
 * Fill the mbedtls_pk_context with the given buffer and apply the password if
 * any is specified. The private key is then checked against the public key
 * stored in the certificate stored in the Identity Handle specified.
 * Note: This function is not making any checks on its input and assumes that
 *     the given parameters are valid.
 */
static TEE_Result privkey_load_and_verify(struct identity_handle_t* ih,
                                          const void* object_buffer,
                                          size_t object_size,
                                          const unsigned char* password,
                                          size_t password_size)
{
    TEE_Result result = 0;
    int result_mbedtls = 0;

    const mbedtls_x509_crt* cert = &(ih->cert_handle.cert);
    mbedtls_pk_context* privkey = &(ih->privkey_handle.privkey);

    ih->privkey_handle.initialized = false;
    mbedtls_pk_init(privkey);
    result_mbedtls = mbedtls_pk_parse_key(privkey,
                                          object_buffer,
                                          object_size,
                                          password,
                                          password_size);

    if (result_mbedtls == 0) {
        result_mbedtls = mbedtls_pk_check_pair(&(cert->pk), privkey);
        if (result_mbedtls == 0) {
            result = TEE_SUCCESS;
            ih->privkey_handle.initialized = true;
        } else {
            EMSG("Check between public and private key failed 0x%x\n",
                 result_mbedtls);

            result = TEE_ERROR_SECURITY;
            mbedtls_pk_init(privkey);
        }

    } else {
        EMSG("Could not parse private key 0x%x\n", result_mbedtls);
        result = TEE_ERROR_BAD_FORMAT;
    }

    return result;
}

TEE_Result dsec_ta_ih_privkey_load(uint32_t parameters_type,
                                   const TEE_Param parameters[3])
{
    TEE_Result result = 0;

    int32_t index_ih = 0;
    struct identity_handle_t* ih = NULL;
    uint32_t filename_size = 0;

    void* object_buffer = NULL;
    size_t object_size = 0;

    const unsigned char* password = NULL;
    size_t password_size = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_MEMREF_INPUT,
                                                    TEE_PARAM_TYPE_MEMREF_INPUT,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_ih = (int32_t)parameters[0].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        if (ih != NULL) {
            if (ih->cert_handle.initialized &&
                !ih->privkey_handle.initialized) {

                password = parameters[2].memref.buffer;
                password_size = parameters[2].memref.size;

                filename_size = (uint32_t)parameters[1].memref.size;

                if (filename_size < DSEC_MAX_NAME_LENGTH) {

                    result = dsec_ta_load_builtin(&object_buffer,
                                                  &object_size,
                                                  parameters[1].memref.buffer);

                    if (result == TEE_SUCCESS) {
                        result = privkey_load_and_verify(ih,
                                                         object_buffer,
                                                         object_size,
                                                         password,
                                                         password_size);

                        dsec_ta_unload_object_memory();

                    } else {
                        EMSG("Could not load the object.\n");
                        /* Return the value from the function that failed */
                    }

                } else {
                    EMSG("Filename buffer is too big.\n");
                    result = TEE_ERROR_EXCESS_DATA;
                }

            } else {
                EMSG("Identity handle element are not valid.\n");
                result = TEE_ERROR_NO_DATA;
            }

        } else {
            EMSG("Identity handle index is not valid %d.\n", index_ih);
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x.\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_privkey_free(struct privkey_handle_t* privkey_handle)
{
    TEE_Result result = 0;

    if (privkey_handle != NULL) {
        if (privkey_handle->initialized) {
            mbedtls_pk_free(&(privkey_handle->privkey));
            privkey_handle->initialized = false;
            result = TEE_SUCCESS;
        } else {
            EMSG("Given element has no private key initialized.\n");
            result = TEE_ERROR_NO_DATA;
        }

    } else {
        EMSG("Pointer to structure privkey_handle is NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_privkey_unload(uint32_t parameters_type,
                                     const TEE_Param parameters[1])
{
    TEE_Result result = 0;
    int32_t index_ih = 0;
    struct identity_handle_t* ih = NULL;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_ih = (int32_t)parameters[0].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        if (ih != NULL) {
            result = dsec_ta_ih_privkey_free(&(ih->privkey_handle));
        } else {
            EMSG("Identity handle is invalid.\n");
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_privkey_sign(uint32_t parameters_type,
                                   TEE_Param parameters[3])
{

    TEE_Result result = 0;

    uint32_t index_lih = 0;
    struct identity_handle_t* lih = NULL;
    const unsigned char* input = NULL;
    size_t input_size = 0;
    unsigned char* signature = NULL;
    size_t signature_size = 0;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {

        index_lih = (int32_t)parameters[1].value.a;
        lih = dsec_ta_get_identity_handle(index_lih);
        if (lih != NULL) {
            if (lih->privkey_handle.initialized) {

                signature = parameters[0].memref.buffer;
                signature_size = parameters[0].memref.size;

                input = parameters[2].memref.buffer;
                input_size = parameters[2].memref.size;

                result = privkey_sign_check_input(input,
                                                  input_size,
                                                  signature,
                                                  signature_size);

                if (result == TEE_SUCCESS) {
                    result = privkey_sign(lih->privkey_handle.privkey.pk_ctx,
                                          input,
                                          input_size,
                                          signature,
                                          &signature_size);

                    if (result == TEE_SUCCESS) {
                        parameters[0].memref.size = signature_size;
                    } else {
                        parameters[0].memref.size = 0;
                    }

                    /* Return result given by the subfunction*/
                }

            } else {
                EMSG("Identity Handle does not contain a private key.\n");
                result = TEE_ERROR_NO_DATA;
            }

        } else {
            EMSG("Identity Handle is invalid.\n");
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
