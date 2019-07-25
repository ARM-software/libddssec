/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ca.h>
#include <dsec_errno.h>
#include <dsec_digest_ca.h>
#include <dsec_print.h>
#include <dsec_ta.h>

int32_t dsec_sha256(uint8_t* digest,
                    uint32_t* digest_size,
                    const uint8_t* input,
                    uint32_t input_size,
                    const struct dsec_instance* instance)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (digest != NULL &&
        digest_size != NULL &&
        input != NULL &&
        input_size != 0) {

        operation.params[0].tmpref.buffer = (void*)digest;
        operation.params[0].tmpref.size = *digest_size;

        operation.params[1].tmpref.buffer = (void*)input;
        operation.params[1].tmpref.size = input_size;

        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_MEMREF_TEMP_INPUT,
                                                TEEC_NONE,
                                                TEEC_NONE);

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_SHA256,
                                     &operation,
                                     &return_origin);

        if (teec_result == TEEC_SUCCESS) {
            digest = operation.params[0].tmpref.buffer;
            *digest_size = operation.params[0].tmpref.size;
            result = DSEC_SUCCESS;
        } else {
            digest = NULL;
            result = dsec_ca_convert_teec_result(teec_result);
            (void)dsec_print("An error occurred: 0x%x.\n", result);
        }
    } else {
        (void)dsec_print("Given parameter is NULL.\n");
        result = DSEC_E_PARAM;
    }

    return result;
}
