/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_hh.h>

static struct handshake_handle_t hh_store[DSEC_TA_MAX_HANDSHAKE_HANDLE];
static uint32_t allocated_handle = 0;

/*
 * Returns a valid index to an element from the array which has not been
 * initialized.
 */
static int32_t find_free_hh_element(void)
{
    int32_t index_hh = 0;

    index_hh = TEE_ERROR_NO_DATA;
    for (uint32_t id = 0; id < DSEC_TA_MAX_HANDSHAKE_HANDLE; id++) {
        if (!hh_store[id].initialized) {
            index_hh = id;
            break;
        }
    }

    return index_hh;
}

/*
 * Checks if a given index leads to an initialized handshake_handle_t (i.e. not
 * out-of-bounds and has its boolean flag `initialized` set.
 */
static bool hh_is_valid(int32_t index_hh)
{
    return (index_hh >= 0) &&
           ((uint32_t)index_hh < DSEC_TA_MAX_HANDSHAKE_HANDLE) &&
           hh_store[index_hh].initialized;
}

TEE_Result dsec_ta_hh_create(uint32_t parameters_type, TEE_Param parameters[1])
{
    TEE_Result result = TEE_SUCCESS;

    int32_t index_hh = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_hh = find_free_hh_element();
        if (index_hh >= 0) {
            parameters[0].value.a = index_hh;
            hh_store[index_hh].initialized = true;
            hh_store[index_hh].dh_pair_handle.initialized = false;
            hh_store[index_hh].dh_public_handle.initialized = false;
            allocated_handle++;
        } else {
            EMSG("Cannot allocate memory for a new handle.\n");
            result = TEE_ERROR_OUT_OF_MEMORY;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_hh_delete(uint32_t parameters_type, TEE_Param parameters[1])
{
    TEE_Result result = TEE_SUCCESS;

    int32_t index_hh = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_hh = (int32_t)parameters[0].value.a;
        if (hh_is_valid(index_hh)) {
            hh_store[index_hh].initialized = false;

            if (hh_store[index_hh].dh_pair_handle.initialized) {
                (void) dsec_ta_hh_dh_free_keypair(
                    &(hh_store[index_hh].dh_pair_handle));
            }

            hh_store[index_hh].dh_public_handle.initialized = false;

            allocated_handle--;
        } else {
            EMSG("Requested handle %d is uninitialized or out-of-bounds.\n",
                 index_hh);

            result = TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

struct handshake_handle_t* dsec_ta_get_handshake_handle(int32_t index_hh)
{
    struct handshake_handle_t* return_hh = NULL;

    if (hh_is_valid(index_hh)) {
        return_hh = &(hh_store[index_hh]);
    }

    return return_hh;
}

TEE_Result dsec_ta_hh_get_info(uint32_t parameters_type,
                               TEE_Param parameters[1])
{
    TEE_Result result = TEE_SUCCESS;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        parameters[0].value.a = DSEC_TA_MAX_HANDSHAKE_HANDLE;
        parameters[0].value.b = allocated_handle;
        result = TEE_SUCCESS;
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
