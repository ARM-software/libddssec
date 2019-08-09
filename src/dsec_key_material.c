/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_key_material.h>
#include <dsec_errno.h>
#include <dsec_print.h>
#include <dsec_ta.h>

int32_t dsec_key_material_create(int32_t* km_handle_id,
                                 const struct dsec_instance* instance,
                                 bool use_gcm,
                                 bool use_256_bits)
{
    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (km_handle_id != NULL) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_NONE,
                                                TEEC_NONE);

        operation.params[1].value.a = (uint32_t)use_gcm;
        operation.params[1].value.b = (uint32_t)use_256_bits;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_KM_CREATE,
                                     &operation,
                                     &return_origin);

        result = dsec_ca_convert_teec_result(teec_result);
        if (teec_result == DSEC_SUCCESS) {
            *km_handle_id = operation.params[0].value.a;
        } else {
            *km_handle_id = -1;
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

int32_t dsec_key_material_copy(int32_t* out_km_handle_id,
                               const struct dsec_instance* instance,
                               int32_t in_km_handle_id)
{
    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (out_km_handle_id != NULL) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_NONE,
                                                TEEC_NONE);

        operation.params[1].value.a = (uint32_t)in_km_handle_id;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_KM_COPY,
                                     &operation,
                                     &return_origin);

        result = dsec_ca_convert_teec_result(teec_result);
        if (teec_result == DSEC_SUCCESS) {
            *out_km_handle_id = operation.params[0].value.a;
        } else {
            *out_km_handle_id = -1;
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

int32_t dsec_key_material_return(uint8_t transformation_kind[4],
                                 uint8_t master_salt[32],
                                 uint8_t sender_key_id[4],
                                 uint8_t master_sender_key[32],
                                 uint8_t receiver_specific_key_id[4],
                                 uint8_t master_receiver_specific_key[32],
                                 const struct dsec_instance* instance,
                                 int32_t km_handle)
{
    TEEC_Result teec_result_1 = 0;
    TEEC_Result teec_result_2 = 0;
    TEEC_Result teec_result_3 = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    const uint32_t transformation_kind_size = 4;
    const uint32_t master_salt_size = 32;
    const uint32_t sender_key_id_size = 4;
    const uint32_t master_sender_key_size = 32;
    const uint32_t receiver_specific_key_id_size = 4;
    const uint32_t master_receiver_specific_key_size = 32;

    if ((transformation_kind != NULL) &&
        (master_salt != NULL) &&
        (sender_key_id != NULL) &&
        (master_sender_key != NULL) &&
        (receiver_specific_key_id != NULL) &&
        (master_receiver_specific_key != NULL)) {

        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_VALUE_INPUT);

        operation.params[2].value.a = (uint32_t)km_handle;
        operation.params[3].value.a = 0;

        operation.params[0].tmpref.buffer = transformation_kind;
        operation.params[0].tmpref.size = transformation_kind_size;
        operation.params[1].tmpref.buffer = master_salt;
        operation.params[1].tmpref.size = master_salt_size;

        teec_result_1 = dsec_ca_invoke(instance,
                                       DSEC_TA_CMD_KM_RETURN,
                                       &operation,
                                       &return_origin);

        operation.params[0].tmpref.buffer = sender_key_id;
        operation.params[0].tmpref.size = sender_key_id_size;
        operation.params[1].tmpref.buffer = master_sender_key;
        operation.params[1].tmpref.size = master_sender_key_size;
        operation.params[3].value.a = 1;

        teec_result_2 = dsec_ca_invoke(instance,
                                       DSEC_TA_CMD_KM_RETURN,
                                       &operation,
                                       &return_origin);

        operation.params[0].tmpref.buffer = receiver_specific_key_id;
        operation.params[0].tmpref.size = receiver_specific_key_id_size;
        operation.params[1].tmpref.buffer = master_receiver_specific_key;
        operation.params[1].tmpref.size = master_receiver_specific_key_size;
        operation.params[3].value.a = 2;

        teec_result_3 = dsec_ca_invoke(instance,
                                       DSEC_TA_CMD_KM_RETURN,
                                       &operation,
                                       &return_origin);

        if ((teec_result_1 == TEEC_SUCCESS) &&
            (teec_result_2 == TEEC_SUCCESS) &&
            (teec_result_3 == TEEC_SUCCESS)) {

            result = DSEC_SUCCESS;
        } else {
            result = DSEC_E_TEE;
            (void)dsec_print("An error occurred: 0x%x - 0x%x - 0x%x - 0x%x\n",
                             result,
                             teec_result_1,
                             teec_result_2,
                             teec_result_3);
        }
    } else {
        result = DSEC_E_PARAM;
        (void)dsec_print("Given parameters are NULL.\n");
    }

    return result;
}

int32_t dsec_key_material_generate(int32_t* out_km_handle_id,
                                   const struct dsec_instance* instance,
                                   int32_t ssh_id)
{
    TEEC_Result teec_result = 0;
    int32_t result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    if (out_km_handle_id != NULL) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_NONE,
                                                TEEC_NONE);

        operation.params[1].value.a = (uint32_t)ssh_id;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_KM_GENERATE,
                                     &operation,
                                     &return_origin);

        result = dsec_ca_convert_teec_result(teec_result);
        if (teec_result == DSEC_SUCCESS) {
            *out_km_handle_id = operation.params[0].value.a;
        } else {
            *out_km_handle_id = -1;
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

int32_t dsec_key_material_register(int32_t* out_km_handle_id,
                                   const struct dsec_instance* instance,
                                   int32_t km_handle_id,
                                   bool is_origin_auth,
                                   bool generate_receiver_specific_key)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};
     if (out_km_handle_id != NULL) {
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_VALUE_INPUT,
                                                TEEC_NONE);

        operation.params[1].value.a = (uint32_t)km_handle_id;
        operation.params[2].value.a = is_origin_auth;
        operation.params[2].value.b = generate_receiver_specific_key;

        teec_result = dsec_ca_invoke(instance,
                                     DSEC_TA_CMD_KM_REGISTER,
                                     &operation,
                                     &return_origin);

        result = dsec_ca_convert_teec_result(teec_result);
        if (teec_result == DSEC_SUCCESS) {
            *out_km_handle_id = operation.params[0].value.a;
        } else {
            *out_km_handle_id = -1;
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

int32_t dsec_key_material_delete(const struct dsec_instance* instance,
                                 int32_t km_handle_id)
{
    int32_t result = 0;
    TEEC_Result teec_result = 0;
    uint32_t return_origin = 0;
    TEEC_Operation operation = {0};

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);

    operation.params[0].value.a = (uint32_t)km_handle_id;

    teec_result = dsec_ca_invoke(instance,
                                 DSEC_TA_CMD_KM_DELETE,
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
