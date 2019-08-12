/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ssh.h>
#include <dsec_ca.h>
#include <dsec_errno.h>
#include <dsec_print.h>
#include <dsec_ta.h>

int32_t dsec_ssh_derive(int32_t* ssh_id,
                        const struct dsec_instance* instance,
                        int32_t hh_id)
{

    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (ssh_id != NULL) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_NONE,
                                                TEEC_NONE);

        operation.params[1].value.a = (uint32_t)hh_id;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_SSH_DERIVE,
                                     &operation,
                                     &return_origin);

        result = dsec_ca_convert_teec_result(teec_result);
        if (teec_result == DSEC_SUCCESS) {
            *ssh_id = operation.params[0].value.a;
        } else {
            *ssh_id = -1;
            (void)dsec_print("An error occurred: TEEC_Result=0x%x, "
                             "DSEC_E=0x%x\n",
                             teec_result,
                             result);
        }
    } else {
        result = DSEC_E_PARAM;
        (void)dsec_print("Given parameter is NULL.\n");
    }

    return result;
}

int32_t dsec_ssh_get_data(void* shared_key,
                          uint32_t* shared_key_size,
                          void* challenge1,
                          uint32_t* challenge1_size,
                          void* challenge2,
                          uint32_t* challenge2_size,
                          const struct dsec_instance* instance,
                          int32_t ssh_id)
{

    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if ((shared_key_size != NULL) &&
        (challenge1_size != NULL) &&
        (challenge2_size != NULL)) {

        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_VALUE_INPUT);

        operation.params[0].tmpref.buffer = shared_key;
        operation.params[0].tmpref.size = *shared_key_size;
        operation.params[1].tmpref.buffer = challenge1;
        operation.params[1].tmpref.size = *challenge1_size;
        operation.params[2].tmpref.buffer = challenge2;
        operation.params[2].tmpref.size = *challenge2_size;
        operation.params[3].value.a = (uint32_t)ssh_id;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_SSH_GET_DATA,
                                     &operation,
                                     &return_origin);

        if (teec_result == TEEC_SUCCESS) {
            *shared_key_size = operation.params[0].tmpref.size;
            *challenge1_size = operation.params[1].tmpref.size;
            *challenge2_size = operation.params[2].tmpref.size;
            result = DSEC_SUCCESS;
        } else {
            *shared_key_size = 0;
            *challenge1_size = 0;
            *challenge2_size = 0;
            result = dsec_ca_convert_teec_result(teec_result);
            (void)dsec_print("An error occurred: 0x%x.\n", result);
        }
    } else {
        result = DSEC_E_PARAM;
        (void)dsec_print("Given parameters are NULL.\n");
    }

    return result;
}

int32_t dsec_ssh_delete(const struct dsec_instance* instance, int32_t ssh_id)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)ssh_id;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_SSH_DELETE,
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

int32_t dsec_ssh_get_info(struct ssh_info_t* ssh_info,
                          const struct dsec_instance* instance)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (ssh_info != NULL) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                                TEEC_NONE,
                                                TEEC_NONE,
                                                TEEC_NONE);

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_SSH_INFO,
                                     &operation,
                                     &return_origin);

        result = dsec_ca_convert_teec_result(teec_result);
        if (result == DSEC_SUCCESS) {
            ssh_info->max_handle = operation.params[0].value.a;
            ssh_info->allocated_handle = operation.params[0].value.b;
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
