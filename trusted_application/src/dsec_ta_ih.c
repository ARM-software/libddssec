/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_ih.h>

static struct identity_handle_t store[DSEC_TA_MAX_IDENTITY_HANDLE];
static uint32_t allocated_handle = 0;

/*
 * Returns a valid index to an element from the array of handle.
 */
static int32_t find_free_ih_element(void)
{
    int32_t index_ih = 0;

    index_ih = TEE_ERROR_NO_DATA;
    for (uint32_t id = 0; id < DSEC_TA_MAX_IDENTITY_HANDLE; id++) {
        if (!store[id].initialized) {
            /*
             * Cast the size_t to a narrower type int32_t the array size cannot
             * have more than INT_MAX elements.
             */
            index_ih = (int32_t)id;
            break;
        }
    }

    return index_ih;
}

/*
 * Checks if a given index leads to an initialized Identity Handle (i.e. not
 * out-of-bounds and has its boolean flag initialized set).
 */
static bool ih_id_valid(int32_t index_ih)
{
    return (index_ih >= 0) &&
           ((uint32_t)index_ih < DSEC_TA_MAX_IDENTITY_HANDLE) &&
           store[index_ih].initialized;
}

TEE_Result dsec_ta_ih_create(uint32_t parameters_type, TEE_Param parameters[1])
{
    TEE_Result result = TEE_SUCCESS;

    int32_t index_ih = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_ih = find_free_ih_element();
        if (index_ih >= 0) {
            parameters[0].value.a = index_ih;
            store[index_ih].initialized = true;
            store[index_ih].ca_handle.initialized = false;
            store[index_ih].cert_handle.initialized = false;
            store[index_ih].privkey_handle.initialized = false;
            allocated_handle++;
        } else {
            EMSG("Cannot allocate more memory for any more handles.\n");
            result = TEE_ERROR_OUT_OF_MEMORY;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_delete(uint32_t parameters_type,
                             const TEE_Param parameters[1])
{
    TEE_Result result = TEE_SUCCESS;

    int32_t index_ih = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_ih = (int32_t)parameters[0].value.a;
        if (ih_id_valid(index_ih)) {
            store[index_ih].initialized = false;
            (void) dsec_ta_ih_ca_free(&(store[index_ih].ca_handle));
            (void) dsec_ta_ih_cert_free(&(store[index_ih].cert_handle));
            (void) dsec_ta_ih_privkey_free(&(store[index_ih].privkey_handle));
            allocated_handle--;
        } else {
            EMSG("Requested handle %d is uninitialized or out-of-bounds.\n",
                 index_ih);

            result = TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

struct identity_handle_t* dsec_ta_get_identity_handle(int32_t ih_id)
{
    struct identity_handle_t* return_ih = NULL;

    if (ih_id_valid(ih_id)) {
        return_ih = &(store[ih_id]);
    }

    return return_ih;
}

TEE_Result dsec_ta_ih_get_info(uint32_t parameters_type,
                               TEE_Param parameters[1])
{
    TEE_Result result = TEE_SUCCESS;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        parameters[0].value.a = DSEC_TA_MAX_IDENTITY_HANDLE;
        parameters[0].value.b = allocated_handle;
        result = TEE_SUCCESS;
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
