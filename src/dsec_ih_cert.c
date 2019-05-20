/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ca.h>
#include <dsec_ih_cert.h>
#include <dsec_errno.h>
#include <dsec_print.h>
#include <dsec_ta.h>
#include <string.h>

int32_t dsec_ih_cert_load(const struct dsec_instance* instance,
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
        (uint32_t)(strnlen(filename, DSEC_IH_CERT_MAX_FILENAME) + 1);

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_IH_CERT_LOAD,
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

int32_t dsec_ih_cert_unload(const struct dsec_instance* instance,
                            int32_t ih_id)
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
                                 DSEC_TA_CMD_IH_CERT_UNLOAD,
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

int32_t dsec_ih_cert_get(uint8_t* output,
                         uint32_t* output_size,
                         const struct dsec_instance* instance,
                         int32_t ih_id)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (output_size != NULL) {

        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_NONE,
                                                TEEC_NONE);


        operation.params[0].tmpref.buffer = output;
        operation.params[0].tmpref.size = *output_size;

        operation.params[1].value.a = (uint32_t)ih_id;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_IH_CERT_GET,
                                     &operation,
                                     &return_origin);

        /* The output length of the buffer was updated within the TA */
        *output_size = operation.params[0].tmpref.size;

        result = dsec_ca_convert_teec_result(teec_result);
        if (result != DSEC_SUCCESS) {
            (void)dsec_print("An error occurred: TEEC_Result=0x%x, "
                             "DSEC_E=0x%x\n",
                             teec_result,
                             result);
        }

    } else {
        (void)dsec_print("Variable output_size is NULL.\n");
        result = DSEC_E_PARAM;
    }

    return result;
}

int32_t dsec_ih_cert_get_sn(uint8_t* output,
                            uint32_t* output_size,
                            const struct dsec_instance* instance,
                            int32_t ih_id)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (output_size != NULL) {

        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_NONE,
                                                TEEC_NONE);


        operation.params[0].tmpref.buffer = output;
        operation.params[0].tmpref.size = *output_size;

        operation.params[1].value.a = (uint32_t)ih_id;

        teec_result  = dsec_ca_invoke(instance,
                                      DSEC_TA_CMD_IH_CERT_GET_SN,
                                      &operation,
                                      &return_origin);

        /* the output length of the buffer was updated within the TA */
        *output_size = operation.params[0].tmpref.size;

        if (teec_result == TEEC_SUCCESS) {
            result = DSEC_SUCCESS;
        } else {
            result = dsec_ca_convert_teec_result(teec_result);
            (void)dsec_print("An error occurred: 0x%x.\n", result);
        }

    } else {
        dsec_print("Variable output_size is NULL.\n");
        result = DSEC_E_PARAM;
    }

    return result;
}

int32_t dsec_ih_cert_get_signature_algorithm(
     uint8_t* output,
     uint32_t* output_size,
     const struct dsec_instance* instance,
     int32_t ih_id)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (output_size != NULL) {

        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_NONE,
                                                TEEC_NONE);

        operation.params[0].tmpref.buffer = output;
        operation.params[0].tmpref.size = *output_size;

        operation.params[1].value.a = (uint32_t)ih_id;

        teec_result =
            dsec_ca_invoke(instance,
                           DSEC_TA_CMD_IH_CERT_GET_SIGNATURE_ALGORITHM,
                           &operation,
                           &return_origin);

        /* the output length of the buffer was updated within the TA */
        *output_size = operation.params[0].tmpref.size;

        if (teec_result == TEEC_SUCCESS) {
            result = DSEC_SUCCESS;
        } else {
            result = dsec_ca_convert_teec_result(teec_result);
            (void)dsec_print("An error occurred: 0x%x.\n", result);
        }

    } else {
        dsec_print("Variable output_size is NULL.\n");
        result = DSEC_E_PARAM;
    }

    return result;
}

int32_t dsec_ih_cert_load_from_buffer(const struct dsec_instance* instance,
                                      int32_t rih_id,
                                      const uint8_t* input_buffer,
                                      uint32_t input_size,
                                      int32_t lih_id)
{
    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_VALUE_INPUT,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)rih_id;

    operation.params[1].tmpref.buffer = (void*)input_buffer;
    operation.params[1].tmpref.size = input_size;

    operation.params[2].value.a = (uint32_t)lih_id;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_IH_CERT_LOAD_FROM_BUFFER,
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

int32_t dsec_ih_cert_verify(const struct dsec_instance* instance,
                            int32_t rih_id,
                            const void* input_buffer,
                            uint32_t input_size,
                            const void* signature,
                            uint32_t signature_size)
{
    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)rih_id;

    operation.params[1].tmpref.buffer = (void*)input_buffer;
    operation.params[1].tmpref.size = input_size;

    operation.params[2].tmpref.buffer = (void*)signature;
    operation.params[2].tmpref.size = signature_size;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_IH_CERT_VERIFY,
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
