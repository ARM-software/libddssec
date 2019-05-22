/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ih_ca.h>
#include <dsec_hh_challenge.h>
#include <dsec_errno.h>
#include <dsec_print.h>
#include <dsec_ta.h>

int32_t dsec_hh_challenge_generate(const struct dsec_instance* instance,
                                   int32_t hh_id,
                                   uint32_t size,
                                   uint8_t challenge_id)
{

    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_VALUE_INPUT,
                                            TEEC_VALUE_INPUT,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)hh_id;
    operation.params[1].value.a = size;
    operation.params[2].value.a = (uint32_t)challenge_id;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_HH_CHALLENGE_GENERATE,
                                 &operation,
                                 &return_origin);

    if (teec_result == TEEC_SUCCESS) {
        result = DSEC_SUCCESS;
    } else {
        result = dsec_ca_convert_teec_result(teec_result);
        (void)dsec_print("An error occurred: 0x%x.\n", result);
    }

    return result;
}

int32_t dsec_hh_challenge_get(void* buffer,
                              uint32_t* buffer_size,
                              const struct dsec_instance* instance,
                              int32_t hh_id,
                              uint8_t challenge_id)
{
    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_VALUE_INPUT,
                                            TEEC_VALUE_INPUT,
                                            TEEC_NONE);

    operation.params[0].tmpref.buffer = (void*)buffer;
    operation.params[0].tmpref.size = *buffer_size;
    operation.params[1].value.a = (uint32_t)hh_id;
    operation.params[2].value.a = (uint32_t)challenge_id;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_HH_CHALLENGE_GET,
                                 &operation,
                                 &return_origin);

    if (teec_result == TEEC_SUCCESS) {
        result = DSEC_SUCCESS;
        *buffer_size = operation.params[0].tmpref.size;
    } else {
        result = dsec_ca_convert_teec_result(teec_result);
        (void)dsec_print("An error occurred: 0x%x.\n", result);
        *buffer_size = 0;
    }

    return result;
}

int32_t dsec_hh_challenge_unload(const struct dsec_instance* instance,
                                 int32_t hh_id)
{

    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)hh_id;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_HH_CHALLENGE_UNLOAD,
                                 &operation,
                                 &return_origin);

    if (teec_result == TEEC_SUCCESS) {
        result = DSEC_SUCCESS;
    } else {
        result = dsec_ca_convert_teec_result(teec_result);
        (void)dsec_print("An error occurred: 0x%x.\n", result);
    }

    return result;
}

int32_t dsec_hh_challenge_set(const struct dsec_instance* instance,
                              int32_t hh_id,
                              const void* buffer,
                              uint32_t buffer_size,
                              uint8_t challenge_id)
{

    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_VALUE_INPUT,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)hh_id;
    operation.params[1].tmpref.buffer = (void*)buffer;
    operation.params[1].tmpref.size = buffer_size;
    operation.params[2].value.a = (uint32_t)challenge_id;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_HH_CHALLENGE_SET,
                                 &operation,
                                 &return_origin);

    if (teec_result == TEEC_SUCCESS) {
        result = DSEC_SUCCESS;
    } else {
        result = dsec_ca_convert_teec_result(teec_result);
        (void)dsec_print("An error occurred: 0x%x.\n", result);
    }

    return result;
}
