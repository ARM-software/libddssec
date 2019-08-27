/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_session_key.h>
#include <dsec_ca.h>
#include <dsec_errno.h>
#include <dsec_print.h>
#include <dsec_ta.h>

int32_t dsec_session_key_create_and_get(uint8_t* session_key,
                                        const struct dsec_instance* instance,
                                        int32_t km_handle_id,
                                        uint32_t session_id,
                                        bool receiver_specific)
{
    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (session_key != NULL) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_NONE);

        operation.params[0].tmpref.buffer = session_key;
        operation.params[0].tmpref.size = DSEC_MAX_SESSION_KEY_SIZE;

        operation.params[1].value.a = (uint32_t)km_handle_id;
        operation.params[2].value.a = session_id;
        operation.params[2].value.b = (uint32_t)receiver_specific;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_SESSION_KEY_CREATE_AND_GET,
                                     &operation,
                                     &return_origin);

        result = dsec_ca_convert_teec_result(teec_result);
        if (result != DSEC_SUCCESS) {
            (void)dsec_print("An error occurred: TEEC_Result=0x%x, "
                             "DSEC_E=0x%x\n",
                             teec_result,
                             result);
        }
    } else {
        dsec_print("NULL session_key\n");
        result = DSEC_E_MEMORY;
    }

    return result;
}
