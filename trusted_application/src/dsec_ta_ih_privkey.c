/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_ih_privkey.h>
#include <dsec_ta_ih.h>
#include <dsec_util.h>
#include <dsec_ta_manage_object.h>

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
