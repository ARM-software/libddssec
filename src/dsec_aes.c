/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_aes.h>
#include <dsec_ca.h>
#include <dsec_errno.h>
#include <dsec_print.h>
#include <dsec_ta.h>
#include <string.h>

int32_t dsec_aes_encrypt(uint8_t* output_data,
                         uint32_t* output_data_size,
                         uint8_t* tag,
                         uint32_t* tag_size,
                         const struct dsec_instance* instance,
                         uint8_t* key_data,
                         uint32_t key_data_size,
                         uint8_t* data_in,
                         uint32_t data_in_size,
                         uint8_t* iv,
                         uint32_t iv_size)
{
    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if ((output_data != NULL) &&
        (output_data_size != NULL) &&
        (tag != NULL) &&
        (tag_size != NULL) &&
        (key_data != NULL) &&
        (key_data_size > 0) &&
        ((key_data_size == 16) || (key_data_size == 32)) &&
        (data_in != NULL) &&
        (data_in_size > 0) &&
        (iv != NULL) &&
        (iv_size > 0) &&
        (*output_data_size >= data_in_size)) {

        memmove(output_data, data_in, data_in_size);
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
                                                TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_MEMREF_TEMP_INPUT,
                                                TEEC_MEMREF_TEMP_INPUT);

        operation.params[0].tmpref.buffer = output_data;
        operation.params[0].tmpref.size = data_in_size;

        operation.params[1].tmpref.buffer = tag;
        operation.params[1].tmpref.size = *tag_size;

        operation.params[2].tmpref.buffer = key_data;
        operation.params[2].tmpref.size = key_data_size;

        operation.params[3].tmpref.buffer = iv;
        operation.params[3].tmpref.size = iv_size;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_AES_ENCRYPT,
                                     &operation,
                                     &return_origin);

        result = dsec_ca_convert_teec_result(teec_result);

        if (result == DSEC_SUCCESS) {
            *output_data_size = operation.params[0].tmpref.size;
            *tag_size = operation.params[1].tmpref.size;
        } else {
            *output_data_size = 0;
            *tag_size = 0;
            (void)dsec_print("An error occurred: TEEC_Result=0x%x, "
                             "DSEC_E=0x%x\n",
                             teec_result,
                             result);
        }
    } else {
        dsec_print("Bad parameters for encrypting using AES");
        result = DSEC_E_PARAM;
    }

    return result;
}

int32_t dsec_aes_decrypt(uint8_t* output_data,
                         uint32_t* output_data_size,
                         const struct dsec_instance* instance,
                         uint8_t* tag,
                         uint32_t tag_size,
                         uint8_t* key_data,
                         uint32_t key_data_size,
                         uint8_t* data_in,
                         uint32_t data_in_size,
                         uint8_t* iv,
                         uint32_t iv_size)
{
    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if ((output_data != NULL) &&
        (output_data_size != NULL) &&
        (*output_data_size >= data_in_size)) {

        memmove(output_data, data_in, data_in_size);
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
                                                TEEC_MEMREF_TEMP_INPUT,
                                                TEEC_MEMREF_TEMP_INPUT,
                                                TEEC_MEMREF_TEMP_INPUT);

        operation.params[0].tmpref.buffer = output_data;
        operation.params[0].tmpref.size = data_in_size;

        operation.params[1].tmpref.buffer = tag;
        operation.params[1].tmpref.size = tag_size;

        operation.params[2].tmpref.buffer = key_data;
        operation.params[2].tmpref.size = key_data_size;

        operation.params[3].tmpref.buffer = iv;
        operation.params[3].tmpref.size = iv_size;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_AES_DECRYPT,
                                     &operation,
                                     &return_origin);

        result = dsec_ca_convert_teec_result(teec_result);

        if (result == DSEC_SUCCESS) {
            *output_data_size = operation.params[0].tmpref.size;
        } else {
            *output_data_size = 0;
            (void)dsec_print("An error occurred: TEEC_Result=0x%x, "
                             "DSEC_E=0x%x\n",
                             teec_result,
                             result);
        }
    } else {
        dsec_print("Bad parameters for decrypting using AES");
        result = DSEC_E_PARAM;
    }

    return result;
}
