/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ca.h>
#include <dsec_errno.h>
#include <dsec_hh.h>
#include <dsec_print.h>
#include <dsec_ta.h>

int32_t dsec_hh_create(int32_t* hh_id, const struct dsec_instance* instance)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (hh_id != NULL) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                                TEEC_NONE,
                                                TEEC_NONE,
                                                TEEC_NONE);

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_HH_CREATE,
                                     &operation,
                                     &return_origin);

        if (teec_result == TEEC_SUCCESS) {
            *hh_id = (int32_t)operation.params[0].value.a;
            result = DSEC_SUCCESS;
        } else {
            *hh_id = -1;
            result = dsec_ca_convert_teec_result(teec_result);
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

int32_t dsec_hh_delete(const struct dsec_instance* instance, int32_t hh_id)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)hh_id;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_HH_DELETE,
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

int32_t dsec_hh_get_info(uint32_t* max_handle,
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
                                     DSEC_TA_CMD_HH_INFO,
                                     &operation,
                                     &return_origin);

        if (teec_result == TEEC_SUCCESS) {
            *max_handle = operation.params[0].value.a;
            *allocated_handle = operation.params[0].value.b;
            result = DSEC_SUCCESS;
        } else {
            result = dsec_ca_convert_teec_result(teec_result);
            (void)dsec_print("An error occurred: TEEC_Result=0x%x, "
                             "DSEC_E=0x%x\n",
                             teec_result,
                             result);
        }

    } else {
        (void)dsec_print("Given parameters are NULL.\n");
        result = DSEC_E_PARAM;
    }

    return result;
}
