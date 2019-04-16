/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ca.h>
#include <dsec_ih.h>
#include <dsec_ih_ca.h>
#include <dsec_errno.h>
#include <dsec_print.h>
#include <dsec_ta.h>
#include <string.h>

int32_t dsec_ih_ca_load(const struct dsec_instance* instance,
                        int32_t ih_id,
                        const char* filename)
{

    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)ih_id;

    operation.params[1].tmpref.buffer = (void*)filename;
    operation.params[1].tmpref.size =
        (uint32_t)(strnlen(filename, DSEC_IH_CA_MAX_FILENAME) + 1);

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_IH_CA_LOAD,
                                 &operation,
                                 &return_origin);

    result = dsec_ca_convert_teec_result(teec_result);
    if (result != DSEC_SUCCESS) {
        (void)dsec_print("An error occurred: TEEC_Result=0x%x, DSEC_E=0x%x\n",
                         teec_result,
                         result);
    }

    return result;
}

int32_t dsec_ih_ca_unload(const struct dsec_instance* instance, int32_t ih_id)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)ih_id;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_IH_CA_UNLOAD,
                                 &operation,
                                 &return_origin);

    result = dsec_ca_convert_teec_result(teec_result);
    if (result != DSEC_SUCCESS) {
        (void)dsec_print("An error occurred: TEEC_Result=0x%x, DSEC_E=0x%x\n",
                         teec_result,
                         result);
    }

    return result;
}
