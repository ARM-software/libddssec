/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_dh.h>
#include <dsec_ta_dh_data.h>
#include <dsec_ta_hh.h>
#include <tee_api.h>
#include <trace.h>
#include <stdbool.h>

static TEE_Result dh_generate_keys(TEE_ObjectHandle* key_pair)
{
    TEE_Result result = 0;
    const uint32_t MAX_NR_DH_PARAMS = 3U;
    TEE_Attribute attributes[MAX_NR_DH_PARAMS];
    uint32_t attribute_count = 0;

    if (key_pair != NULL) {
        result = TEE_AllocateTransientObject(TEE_TYPE_DH_KEYPAIR,
                                             DSEC_TA_DH_MAX_KEY_BITS,
                                             key_pair);
        if (result == TEE_SUCCESS) {

            TEE_InitRefAttribute(&attributes[attribute_count++],
                                 TEE_ATTR_DH_PRIME,
                                 DH_MODP_2048_256_PRIME,
                                 DH_MODP_2048_256_PRIME_SIZE);

            TEE_InitRefAttribute(&attributes[attribute_count++],
                                 TEE_ATTR_DH_BASE,
                                 DH_MODP_2048_256_GENERATOR,
                                 DH_MODP_2048_256_GENERATOR_SIZE);

            TEE_InitRefAttribute(&attributes[attribute_count++],
                                 TEE_ATTR_DH_SUBPRIME,
                                 DH_MODP_2048_256_SUBPRIME,
                                 DH_MODP_2048_256_SUBPRIME_SIZE);

            result = TEE_GenerateKey(*key_pair,
                                     DSEC_TA_DH_MAX_KEY_BITS,
                                     attributes,
                                     attribute_count);

            if (result != TEE_SUCCESS) {
                EMSG("Cannot generate DH key pair.\n");
                /* Return result code from TEE_GenerateKey */
            }

        } else {
            EMSG("Cannot allocate TEE_ObjectHandle for DH keys.\n");
            /* Return result code from TEE_AllocateTransientObject */
        }

    } else {
        EMSG("Parameter is NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_hh_dh_generate_keys(uint32_t parameters_type,
                                       TEE_Param parameters[1])
{
    TEE_Result result = 0;
    uint32_t index_hh = 0;
    struct handshake_handle_t* hh = NULL;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_hh = (int32_t)parameters[0].value.a;
        hh = dsec_ta_get_handshake_handle(index_hh);

        if (hh != NULL) {
            if (!hh->dh_pair_handle.initialized) {
                result = dh_generate_keys(&(hh->dh_pair_handle.key_pair));

                if (result == TEE_SUCCESS) {
                    hh->dh_pair_handle.initialized = true;
                }

            } else {
                EMSG("Handshake handle element key_pair is already set.\n");
                result = TEE_ERROR_NO_DATA;
            }

        } else {
            EMSG("Handshake Handle index is not valid %d.\n", index_hh);
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x.\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_hh_dh_get_public(uint32_t parameters_type,
                                    TEE_Param parameters[2])
{
    TEE_Result result = 0;
    uint32_t index_hh = 0;
    struct handshake_handle_t* hh = NULL;
    uint32_t output_size = 0;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_hh = (int32_t)parameters[1].value.a;
        hh = dsec_ta_get_handshake_handle(index_hh);

        output_size = parameters[0].memref.size;
        if (hh != NULL) {
            if (hh->dh_pair_handle.initialized) {

                /* Retrieve the public attributes */
                result = TEE_GetObjectBufferAttribute(
                    hh->dh_pair_handle.key_pair,
                    TEE_ATTR_DH_PUBLIC_VALUE,
                    parameters[0].memref.buffer,
                    &output_size);

                if (result == TEE_SUCCESS) {
                    parameters[0].memref.size = output_size;
                } else {
                    parameters[0].memref.size = 0;
                    EMSG("Cannot get DH public key.\n");
                    /* Return result code from TEE_GetObjectBufferAttribute */
                }

            } else {
                EMSG("Handshake handle element key_pair is not set.\n");
                result = TEE_ERROR_NO_DATA;
            }

        } else {
            EMSG("Handshake Handle index is not valid %d.\n", index_hh);
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x.\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_hh_dh_free_keypair(struct dh_pair_handle_t* dh_pair_handle)
{
    TEE_Result result = 0;

    if ((dh_pair_handle != NULL) && dh_pair_handle->initialized) {
        dh_pair_handle->initialized = false;
        TEE_FreeTransientObject(dh_pair_handle->key_pair);
        result = TEE_SUCCESS;
    } else {
        DMSG("Handshake handle element key_pair is not set.\n");
        result = TEE_ERROR_NO_DATA;
    }

    return result;
}

TEE_Result dsec_ta_hh_dh_unload(uint32_t parameters_type,
                                TEE_Param parameters[1])
{
    TEE_Result result = 0;
    uint32_t index_hh = 0;
    struct handshake_handle_t* hh = NULL;
    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_hh = (int32_t)parameters[0].value.a;
        hh = dsec_ta_get_handshake_handle(index_hh);

        if (hh != NULL) {
            (void)dsec_ta_hh_dh_free_keypair(&(hh->dh_pair_handle));
            (void)dsec_ta_hh_dh_free_keypair(&(hh->dh_pair_handle));
            hh->dh_public_handle.initialized = false;
            result = TEE_SUCCESS;
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

TEE_Result dsec_ta_hh_dh_set_public(uint32_t parameters_type,
                                    TEE_Param parameters[2])
{
    TEE_Result result = 0;
    uint32_t index_hh = 0;
    struct handshake_handle_t* hh = NULL;
    const void* input = NULL;
    size_t input_size = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_MEMREF_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_hh = (int32_t)parameters[0].value.a;
        hh = dsec_ta_get_handshake_handle(index_hh);

        input = parameters[1].memref.buffer;
        input_size = parameters[1].memref.size;

        if (hh != NULL) {
            if (input_size <= DSEC_TA_DH_MAX_KEY_BYTES) {
                if (!hh->dh_public_handle.initialized) {
                    TEE_MemMove(hh->dh_public_handle.key, input, input_size);
                    hh->dh_public_handle.initialized = true;
                    hh->dh_public_handle.key_size = input_size;
                } else {
                    EMSG("Element dh_public is already set.\n");
                    result = TEE_ERROR_NO_DATA;
                }

            } else {
                EMSG("Input buffer is too big.\n");
                result = TEE_ERROR_OVERFLOW;
            }

        } else {
            EMSG("Handshake Handle index is not valid %d.\n", index_hh);
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x.\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
