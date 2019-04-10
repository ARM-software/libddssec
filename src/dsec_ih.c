/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ca.h>
#include <dsec_errno.h>
#include <dsec_ih.h>
#include <dsec_print.h>
#include <dsec_ta.h>

int32_t dsec_ih_create(int32_t* ih_id, const struct dsec_instance* instance)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (ih_id != NULL) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                                TEEC_NONE,
                                                TEEC_NONE,
                                                TEEC_NONE);

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_IH_CREATE,
                                     &operation,
                                     &return_origin);

        if (teec_result == TEEC_SUCCESS) {
            *ih_id = (int32_t)operation.params[0].value.a;
            result = DSEC_SUCCESS;
        } else {
            *ih_id = -1;
            result = dsec_ca_convert_teec_result(teec_result);
            (void)dsec_print("An error occurred: 0x%x.\n", result);
        }
    } else {
        (void)dsec_print("Given parameter is NULL.\n");
        result = DSEC_E_PARAM;
    }

    return result;
}

int32_t dsec_ih_delete(const struct dsec_instance* instance, int32_t ih_id)
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
                                 DSEC_TA_CMD_IH_DELETE,
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

int32_t dsec_ih_get_info(uint32_t* max_handle,
                         uint32_t* allocated_handle,
                         const struct dsec_instance* instance)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if ((max_handle != NULL) && (allocated_handle != NULL)) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                                TEEC_NONE,
                                                TEEC_NONE,
                                                TEEC_NONE);

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_IH_INFO,
                                     &operation,
                                     &return_origin);

        if (teec_result == TEEC_SUCCESS) {
            *max_handle = operation.params[0].value.a;
            *allocated_handle = operation.params[0].value.b;
            result = DSEC_SUCCESS;
        } else {
            result = dsec_ca_convert_teec_result(teec_result);
            (void)dsec_print("An error occurred: 0x%x.\n", result);
        }

    } else {
        (void)dsec_print("Given parameters are NULL.\n");
        result = DSEC_E_PARAM;
    }

    return result;
}
