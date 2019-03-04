/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta.h>
#include <test_manage_object_ca.h>
#include <stdint.h>

TEEC_Result load_object_builtin(const char* name,
                                size_t name_length,
                                struct dsec_instance* instance)
{
    uint32_t origin = 0;
    TEEC_Operation operation = {0};
    TEEC_Result result = 0;

    operation.params[0].tmpref.buffer = (void*)name;
    operation.params[0].tmpref.size = name_length;

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);

    result = dsec_ca_invoke(instance,
                            DSEC_TA_CMD_LOAD_OBJECT_BUILTIN,
                            &operation,
                            &origin);

    return result;
}

TEEC_Result unload_object(struct dsec_instance* instance)
{
    uint32_t origin = 0;
    TEEC_Operation operation = {0};
    TEEC_Result result = 0;

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);

    result = dsec_ca_invoke(instance,
                            DSEC_TA_CMD_UNLOAD_OBJECT,
                            &operation,
                            &origin);

    return result;
}
