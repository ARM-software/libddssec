/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_challenge.h>
#include <dsec_ta_hh.h>
#include <tee_api.h>
#include <trace.h>
#include <stdbool.h>

TEE_Result dsec_ta_hh_challenge_generate(uint32_t parameters_type,
                                         const TEE_Param parameters[3])
{
    TEE_Result result = 0;
    uint32_t index_hh = 0;
    struct handshake_handle_t* hh = NULL;
    struct shared_secret_handle_t* shared_secret_h = NULL;
    struct challenge_handle_t* challenge_handle = NULL;
    uint32_t size = 0;
    uint8_t challenge_id = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE);


    if (parameters_type == expected_types) {
        index_hh = (int32_t)parameters[0].value.a;
        size = parameters[1].value.a;
        challenge_id = (uint8_t)parameters[2].value.a;
        hh = dsec_ta_get_handshake_handle(index_hh);

        if (hh != NULL) {
            shared_secret_h = &(hh->shared_secret_handle);

            if (challenge_id == 1) {
                challenge_handle = &(shared_secret_h->challenge1_handle);
            } else if (challenge_id == 2) {
                challenge_handle = &(shared_secret_h->challenge2_handle);
            } else {
                challenge_handle = NULL;
            }

            if ((challenge_handle != NULL) && !challenge_handle->initialized) {

                if (size <= DSEC_TA_CHALLENGE_MAX_DATA_SIZE) {
                    TEE_GenerateRandom(challenge_handle->data, size);
                    challenge_handle->initialized = true;
                    challenge_handle->data_size = size;
                } else {
                    challenge_handle->data_size = 0;
                    challenge_handle->initialized = false;
                    result = TEE_ERROR_SHORT_BUFFER;
                    EMSG("Challenge size requested is too big.\n");
                }

            } else {
                result = TEE_ERROR_NO_DATA;
                EMSG("Element local_challenge is already set.\n");
            }

        } else {
            result = TEE_ERROR_BAD_PARAMETERS;
            EMSG("Handshake Handle index is not valid %d.\n", index_hh);
        }

    } else {
        result = TEE_ERROR_BAD_PARAMETERS;
        EMSG("Bad parameters types: 0x%x.\n", parameters_type);
    }

    return result;
}

TEE_Result dsec_ta_hh_challenge_get(uint32_t parameters_type,
                                    TEE_Param parameters[3])
{
    TEE_Result result = 0;
    uint32_t index_hh = 0;
    struct handshake_handle_t* hh = NULL;
    struct shared_secret_handle_t* shared_secret_h = NULL;
    struct challenge_handle_t* challenge_handle = NULL;
    uint8_t challenge_id = 0;
    void* output = NULL;
    size_t output_size = 0;
    size_t challenge_size = 0;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        output = parameters[0].memref.buffer;
        output_size = parameters[0].memref.size;

        index_hh = (int32_t)parameters[1].value.a;
        hh = dsec_ta_get_handshake_handle(index_hh);

        challenge_id = (uint8_t)parameters[2].value.a;

        if (hh != NULL) {
            shared_secret_h = &(hh->shared_secret_handle);

            if (challenge_id == 1) {
                challenge_handle = &(shared_secret_h->challenge1_handle);
            } else if (challenge_id == 2) {
                challenge_handle = &(shared_secret_h->challenge2_handle);
            } else {
                challenge_handle = NULL;
            }

            if ((challenge_handle != NULL) && challenge_handle->initialized) {
                challenge_size = challenge_handle->data_size;
                if (output_size >= challenge_size) {
                    TEE_MemMove(output, challenge_handle->data, challenge_size);
                    parameters[0].memref.size = challenge_size;
                    result = TEE_SUCCESS;
                } else {
                    parameters[0].memref.size = 0;
                    result = TEE_ERROR_SHORT_BUFFER;
                    EMSG("Output buffer is too small.\n");
                }

            } else {
                result = TEE_ERROR_NO_DATA;
                EMSG("Challenge is not set.\n");
            }

        } else {
            result = TEE_ERROR_BAD_PARAMETERS;
            EMSG("Handshake Handle index is not valid %d.\n", index_hh);
        }

    } else {
        result = TEE_ERROR_BAD_PARAMETERS;
        EMSG("Bad parameters types: 0x%x.\n", parameters_type);
    }

    return result;
}

TEE_Result dsec_ta_hh_challenge_unload(uint32_t parameters_type,
                                       const TEE_Param parameters[1])
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
            hh->shared_secret_handle.challenge1_handle.initialized = false;
            hh->shared_secret_handle.challenge1_handle.data_size = 0;
            hh->shared_secret_handle.challenge2_handle.initialized = false;
            hh->shared_secret_handle.challenge2_handle.data_size = 0;
        } else {
            result = TEE_ERROR_BAD_PARAMETERS;
            EMSG("Handshake handle is invalid.\n");
        }

    } else {
        result = TEE_ERROR_BAD_PARAMETERS;
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
    }

    return result;
}

static TEE_Result set_remote_challenge(struct handshake_handle_t* hh,
                                       const void* input,
                                       size_t input_size,
                                       uint8_t challenge_id)
{
    TEE_Result result = 0;
    struct challenge_handle_t* challenge_handle = NULL;

    if (challenge_id == 1) {
        challenge_handle = &(hh->shared_secret_handle.challenge1_handle);
    } else if (challenge_id == 2) {
        challenge_handle = &(hh->shared_secret_handle.challenge2_handle);
    } else {
        challenge_handle = NULL;
    }


    if (challenge_handle != NULL) {
        if (input_size <= DSEC_TA_CHALLENGE_MAX_DATA_SIZE) {

            if (!challenge_handle->initialized) {
                TEE_MemMove(challenge_handle->data, input, input_size);

                challenge_handle->data_size = input_size;
                challenge_handle->initialized = true;
            } else {
                result = TEE_ERROR_NO_DATA;
                EMSG("Challenge is already set.\n");
            }

        } else {
            result = TEE_ERROR_OVERFLOW;
            EMSG("Input buffer is too big.\n");
        }
    } else {
        result = TEE_ERROR_BAD_PARAMETERS;
        EMSG("Challenge id must be 1 or 2.\n");
    }

    return result;
}

TEE_Result dsec_ta_hh_challenge_set(uint32_t parameters_type,
                                    const TEE_Param parameters[3])
{
    TEE_Result result = 0;
    uint32_t index_hh = 0;
    struct handshake_handle_t* hh = NULL;
    const void* input = NULL;
    size_t input_size = 0;
    uint8_t challenge_id = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_MEMREF_INPUT,
                                                    TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_hh = (int32_t)parameters[0].value.a;
        hh = dsec_ta_get_handshake_handle(index_hh);

        input = parameters[1].memref.buffer;
        input_size = parameters[1].memref.size;

        challenge_id = (uint8_t)parameters[2].value.a;

        if ((hh != NULL) && hh->initialized) {
            result = set_remote_challenge(hh, input, input_size, challenge_id);
        } else {
            result = TEE_ERROR_BAD_PARAMETERS;
            EMSG("Handshake Handle index is not valid %d.\n", index_hh);
        }

    } else {
        result = TEE_ERROR_BAD_PARAMETERS;
        EMSG("Bad parameters types: 0x%x.\n", parameters_type);
    }

    return result;
}
