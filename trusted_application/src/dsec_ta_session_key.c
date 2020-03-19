/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_session_key.h>
#include <dsec_ta_hmac.h>
#include <dsec_ta_key_material.h>
#include <dsec_ta_aes.h>
#include <string.h>

#define DSEC_KEY_LENGTH_SHORT (32U)
#define DSEC_KEY_LENGTH_LONG (16U)

/*!
 * The computation of the session key follows the OMG specification. Have a look
 * at the documentation for more details.
 */
static TEE_Result compute_session_key(
    uint8_t session_key[DSEC_TA_MAX_SESSION_KEY_SIZE],
    bool receiver_specific,
    int32_t km_handle_id,
    uint32_t session_id)
{
    const size_t max_input_sequence_size = 18;
    const size_t max_input_key_size = 32;
    const size_t session_id_size = 4;
    TEE_Result result = 0;
    uint8_t source[max_input_sequence_size +
                   max_input_key_size +
                   session_id_size];

    const uint8_t seq[] = "SessionKey";
    const uint32_t seq_size = sizeof(seq) - 1;

    const uint8_t receiver_seq[] = "SessionReceiverKey";
    const uint32_t receiver_seq_size = sizeof(receiver_seq) - 1;

    const uint8_t* key = NULL;
    uint32_t key_len = 0;
    const struct key_material_t* key_material = NULL;

    uint32_t source_size = 0;
    uint32_t session_key_size = DSEC_TA_MAX_SESSION_KEY_SIZE;

    key_material = key_material_get(km_handle_id);
    if ((session_key != NULL) && (key_material != NULL)) {
        if (key_material->transformation_kind[3] != 0) {

            if (key_material->transformation_kind[3] >= 3) {
                key_len = DSEC_KEY_LENGTH_SHORT;
            } else {
                key_len = DSEC_KEY_LENGTH_LONG;
            }

            if (receiver_specific) {
                TEE_MemMove(source, receiver_seq, receiver_seq_size);
                source_size = receiver_seq_size;
                key = key_material->master_receiver_specific_key;
            } else {
                TEE_MemMove(source, seq, seq_size);
                source_size = seq_size;
                key = key_material->master_sender_key;
            }

            TEE_MemMove(source + source_size,
                        key_material->master_salt,
                        key_len);

            source_size += key_len;
            TEE_MemMove(source + source_size,
                        &session_id,
                        sizeof(session_id));

            source_size += sizeof(session_id);

            result = dsec_ta_hmac_256(session_key,
                                      &session_key_size,
                                      key,
                                      key_len,
                                      source,
                                      source_size);
        } else {
            EMSG("Transformation kind cannot be NONE.\n");
            result = TEE_ERROR_BAD_STATE;
        }

    } else {
        EMSG("Given handle %d is invalid or session key is NULL.\n",
             km_handle_id);

        result = TEE_ERROR_NO_DATA;
    }

    return result;
}

TEE_Result dsec_ta_session_key_create_and_get(uint32_t parameters_type,
                                              TEE_Param parameters[3])
{
    TEE_Result result = TEE_SUCCESS;

    int32_t km_handle_id = 0;
    uint32_t session_id = 0;
    bool receiver_specific = 0;

    uint8_t* output = 0;
    uint32_t output_size = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        output = parameters[0].memref.buffer;
        output_size = parameters[0].memref.size;

        if (output_size >= DSEC_TA_MAX_SESSION_KEY_SIZE) {
            parameters[0].memref.size = 0;

            km_handle_id = (int32_t)parameters[1].value.a;
            session_id = parameters[2].value.a;
            receiver_specific = (parameters[2].value.b > 0) ? true : false;

            result = compute_session_key(output,
                                         receiver_specific,
                                         km_handle_id,
                                         session_id);

            if (result == TEE_SUCCESS) {
                parameters[0].memref.size = DSEC_TA_MAX_SESSION_KEY_SIZE;
            } else {
                parameters[0].memref.size = 0;
            }

        } else {
            EMSG("Given buffer is too small: %u\n", output_size);
            result = TEE_ERROR_SHORT_BUFFER;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

