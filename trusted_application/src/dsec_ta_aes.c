/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * OP-TEE TA specific for AES128 and AES256 (GCM)
 */

#include <dsec_ta_aes.h>
#include <stdbool.h>
#include <string.h>

TEE_OperationHandle aes_encrypt_op = TEE_HANDLE_NULL;
TEE_OperationHandle aes_decrypt_op = TEE_HANDLE_NULL;

/* Temporary buffer used for decrypting data */
static uint8_t static_output_data[DSEC_TA_AES_STATIC_OUTPUT_SIZE] = {0};

TEE_Result dsec_ta_aes_init(void)
{
    static bool is_allocated = false;
    TEE_Result result = 0;

    if (!is_allocated) {
        result = TEE_AllocateOperation(&aes_encrypt_op,
                                       TEE_ALG_AES_GCM,
                                       TEE_MODE_ENCRYPT,
                                       DSEC_TA_AES_MAX_KEY_SIZE);

        if (result == TEE_SUCCESS) {
            result = TEE_AllocateOperation(&aes_decrypt_op,
                                           TEE_ALG_AES_GCM,
                                           TEE_MODE_DECRYPT,
                                           DSEC_TA_AES_MAX_KEY_SIZE);

            if (result != TEE_SUCCESS) {
                EMSG("Cannot allocate AES decrypt operation. Error 0x%x\n",
                     result);
            }
        } else {
            EMSG("Cannot allocate AES encrypt operation. Error 0x%x\n", result);
        }

    } else {
        result = TEE_SUCCESS;
    }

    return result;
}

TEE_Result aes_encrypt(uint8_t* output_data,
                       uint32_t* output_data_size,
                       uint8_t* tag,
                       uint32_t* tag_size,
                       const uint8_t* key_data,
                       uint32_t key_data_size,
                       const uint8_t* data_in,
                       uint32_t data_in_size,
                       const uint8_t* iv,
                       uint32_t iv_size)
{
    TEE_Result result = TEE_SUCCESS;

    if ((output_data != NULL) &&
        (tag != NULL) &&
        (tag_size != NULL) &&
        (*tag_size > 0) &&
        (*tag_size <= DSEC_TA_AES_MAX_TAG_SIZE) &&
        (key_data != NULL) &&
        ((key_data_size == 16) || (key_data_size == 32)) &&
        (data_in != NULL) &&
        (data_in_size > 0) &&
        (iv != NULL) &&
        (iv_size > 0)) {

        TEE_ObjectHandle key_object = (TEE_ObjectHandle)NULL;

        /* Allocate key handle */
        result = TEE_AllocateTransientObject(TEE_TYPE_AES,
                                             DSEC_TA_AES_MAX_KEY_SIZE,
                                             &key_object);

        if (result == TEE_SUCCESS) {
            TEE_Attribute attribute;
            /* Set the key data attributes */
            TEE_InitRefAttribute(&attribute,
                                 TEE_ATTR_SECRET_VALUE,
                                 key_data,
                                 key_data_size);

            result = TEE_PopulateTransientObject(key_object, &attribute, 1);

            if (result == TEE_SUCCESS) {
                /* Set operation key. */
                result = TEE_SetOperationKey(aes_encrypt_op, key_object);
                if (result == TEE_SUCCESS) {
                    /* Initialize authenticated encryption/decryption */
                    result = TEE_AEInit(aes_encrypt_op,
                                        iv,
                                        iv_size,
                                        *tag_size*8 /* size in bits */,
                                        0 /* AADLen (unused for GCM) */,
                                        0 /* payloadLen (unused for GCM) */);

                    if (result == TEE_SUCCESS) {
                        /* Update data */
                        result = TEE_AEEncryptFinal(aes_encrypt_op,
                                                    data_in,
                                                    data_in_size,
                                                    output_data,
                                                    output_data_size,
                                                    tag,
                                                    tag_size);

                        if (result != TEE_SUCCESS) {
                            EMSG("Cannot do the encryption. Error 0x%x\n",
                                 result);
                        }

                    } else {
                        EMSG("Cannot initialize encryption with iv size:"
                             "%u and tag size %u. "
                             "Error 0x%x\n",
                             iv_size,
                             *tag_size,
                             result);
                    }

                } else {
                    EMSG("Cannot set key for encryption. Error 0x%x\n",
                         result);
                }

                TEE_FreeTransientObject(key_object);

            } else {
                EMSG("Cannot create the key of size %d. Error 0x%x\n",
                     key_data_size,
                     result);
            }

        } else {
            EMSG("Cannot allocate AES-GCM key object. Error 0x%x\n", result);
        }
    } else {
        EMSG("Invalid parameters for encrypting a buffer with AES");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result aes_decrypt(uint8_t* output_data,
                       uint32_t* output_data_size,
                       uint8_t* tag,
                       uint32_t* tag_size,
                       const uint8_t* key_data,
                       uint32_t key_data_size,
                       const uint8_t* data_in,
                       uint32_t data_in_size,
                       const uint8_t* iv,
                       uint32_t iv_size)
{
    TEE_Result result = TEE_SUCCESS;

    if ((output_data != NULL) &&
        (tag != NULL) &&
        (tag_size != NULL) &&
        (*tag_size > 0) &&
        (*tag_size <= DSEC_TA_AES_MAX_TAG_SIZE) &&
        (key_data != NULL) &&
        ((key_data_size == 16) || (key_data_size == 32)) &&
        (data_in != NULL) &&
        (data_in_size > 0) &&
        (iv != NULL) &&
        (iv_size > 0)) {

        TEE_ObjectHandle key_object = (TEE_ObjectHandle)NULL;

        /* Allocate key handle */
        result = TEE_AllocateTransientObject(TEE_TYPE_AES,
                                             DSEC_TA_AES_MAX_KEY_SIZE,
                                             &key_object);

        if (result == TEE_SUCCESS) {
            TEE_Attribute attribute;
            /* Set the key data attributes */
            TEE_InitRefAttribute(&attribute,
                                 TEE_ATTR_SECRET_VALUE,
                                 key_data,
                                 key_data_size);

            result = TEE_PopulateTransientObject(key_object, &attribute, 1);

            if (result == TEE_SUCCESS) {
                /* Set operation key. */
                result = TEE_SetOperationKey(aes_decrypt_op, key_object);
                if (result == TEE_SUCCESS) {
                    /* Initialize authenticated encryption/decryption */
                    result = TEE_AEInit(aes_decrypt_op,
                                        iv,
                                        iv_size,
                                        *tag_size*8 /* size in bits */,
                                        0 /* AADLen (unused for GCM) */,
                                        0 /* payloadLen (unused for GCM) */);

                    if (result == TEE_SUCCESS) {
                        result = TEE_AEDecryptFinal(aes_decrypt_op,
                                                    data_in,
                                                    data_in_size,
                                                    static_output_data,
                                                    output_data_size,
                                                    tag,
                                                    *tag_size);


                        /* Using the output buffer in TEE_AEUpdate directly
                         * causes TEE_ERROR_MAC_INVALID, so it is memmove-d
                         * from here. */
                        TEE_MemMove(output_data,
                                    static_output_data,
                                    *output_data_size);

                        memset(static_output_data,
                               0,
                               DSEC_TA_AES_STATIC_OUTPUT_SIZE);

                        if (result != TEE_SUCCESS) {
                            EMSG("Cannot perform decryption. Error 0x%x\n",
                                 result);
                        }

                    } else {
                        EMSG("Cannot initialize decryption with iv size:"
                             " %u and tag size %u. "
                             "Error 0x%x\n",
                             iv_size,
                             *tag_size,
                             result);
                    }

                } else {
                    EMSG("Cannot set key for decryption. Error 0x%x\n",
                         result);
                }

                TEE_FreeTransientObject(key_object);

            } else {
                EMSG("Cannot create the key of size %d. Error 0x%x\n",
                     key_data_size,
                     result);
            }

        } else {
            EMSG("Cannot allocate AES-GCM key object. Error 0x%x\n", result);
        }
    } else {
        EMSG("Invalid parameters for decrypting a buffer with AES");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_aes_encrypt(uint32_t parameters_type,
                               TEE_Param parameters[4])
{
    TEE_Result result = TEE_SUCCESS;

    uint8_t* tag = NULL;
    uint32_t tag_size = 0;

    const uint8_t* key_data = NULL;
    uint32_t key_data_size = 0;

    const uint8_t* data_in = NULL;
    uint32_t data_in_size = 0;

    const uint8_t* iv = NULL;
    uint32_t iv_size = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT);

    if (parameters_type == expected_types) {

        data_in = parameters[0].memref.buffer;
        data_in_size = parameters[0].memref.size;

        /* Reuse input buffer for output */
        uint8_t* output_data = parameters[0].memref.buffer;
        uint32_t output_data_size = data_in_size;

        tag = parameters[1].memref.buffer;
        tag_size = parameters[1].memref.size;

        key_data = parameters[2].memref.buffer;
        key_data_size = parameters[2].memref.size;

        iv = parameters[3].memref.buffer;
        iv_size = parameters[3].memref.size;

        result = aes_encrypt(output_data,
                             &output_data_size,
                             tag,
                             &tag_size,
                             key_data,
                             key_data_size,
                             data_in,
                             data_in_size,
                             iv,
                             iv_size);

        if (result == TEE_SUCCESS) {
            parameters[0].memref.size = data_in_size;
            parameters[1].memref.size = tag_size;
        } else {
            parameters[0].memref.size = 0;
            parameters[1].memref.size = 0;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_aes_decrypt(uint32_t parameters_type,
                               TEE_Param parameters[4])
{
    TEE_Result result = TEE_SUCCESS;

    uint8_t* tag = NULL;
    uint32_t tag_size = 0;

    const uint8_t* key_data = NULL;
    uint32_t key_data_size = 0;

    const uint8_t* data_in = NULL;
    uint32_t data_in_size = 0;

    const uint8_t* iv = NULL;
    uint32_t iv_size = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT);

    if (parameters_type == expected_types) {
        data_in = parameters[0].memref.buffer;
        data_in_size = parameters[0].memref.size;

        /* Reuse input buffer for output */
        uint8_t* output_data = parameters[0].memref.buffer;
        uint32_t output_data_size = data_in_size;

        tag = parameters[1].memref.buffer;
        tag_size = parameters[1].memref.size;

        key_data = parameters[2].memref.buffer;
        key_data_size = parameters[2].memref.size;

        iv = parameters[3].memref.buffer;
        iv_size = parameters[3].memref.size;

        result = aes_decrypt(output_data,
                             &output_data_size,
                             tag,
                             &tag_size,
                             key_data,
                             key_data_size,
                             data_in,
                             data_in_size,
                             iv,
                             iv_size);

        if (result == TEE_SUCCESS) {
            parameters[0].memref.size = data_in_size;
        } else {
            parameters[0].memref.size = 0;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
