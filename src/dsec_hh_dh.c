/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_hh_dh.h>
#include <dsec_errno.h>
#include <dsec_print.h>
#include <dsec_ta.h>

int32_t dsec_hh_dh_generate(const struct dsec_instance* instance, int32_t hh_id)
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
                                 DSEC_TA_CMD_HH_DH_GENERATE_KEYS,
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

int32_t dsec_hh_dh_get_public(void* buffer,
                              uint32_t* buffer_size,
                              const struct dsec_instance* instance,
                              int32_t hh_id)
{
    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (buffer_size != NULL) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_NONE,
                                                TEEC_NONE);

        operation.params[0].tmpref.buffer = (void*)buffer;
        operation.params[0].tmpref.size = *buffer_size;

        operation.params[1].value.a = (uint32_t)hh_id;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_HH_DH_GET_PUBLIC,
                                     &operation,
                                     &return_origin);

        result = dsec_ca_convert_teec_result(teec_result);
        if (result == DSEC_SUCCESS) {
            *buffer_size = operation.params[0].tmpref.size;
        } else {
            (void)dsec_print("An error occurred: TEEC_Result=0x%x, "
                             "DSEC_E=0x%x\n",
                             teec_result,
                             result);
        }
    } else {
        (void)dsec_print("Given parameter is NULL.\n");
        result = DSEC_E_PARAM;
    }

    return result;
}

int32_t dsec_hh_dh_unload(const struct dsec_instance* instance, int32_t hh_id)
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
                                 DSEC_TA_CMD_HH_DH_UNLOAD,
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

int32_t dsec_hh_dh_set_public(const struct dsec_instance* instance,
                              int32_t hh_id,
                              const void* buffer,
                              uint32_t buffer_size)
{

    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)hh_id;
    operation.params[1].tmpref.buffer = (void*)buffer;
    operation.params[1].tmpref.size = buffer_size;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_HH_DH_SET_PUBLIC,
                                 &operation,
                                 &return_origin);

    result = dsec_ca_convert_teec_result(teec_result);
    if (result == DSEC_SUCCESS) {
        (void)dsec_print("An error occurred: TEEC_Result=0x%x, DSEC_E=0x%x\n",
                         teec_result,
                         result);
    }

    return result;
}
