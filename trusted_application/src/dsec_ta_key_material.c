/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_digest.h>
#include <dsec_ta_key_material.h>
#include <dsec_ta_hmac.h>
#include <dsec_ta_ssh.h>
#include <dsec_errno.h>
#include <string.h>

/* See the OMG specification for the meaning of those data */
#define COOKIE_SALT "keyexchange salt"
#define COOKIE_KEY  "key exchange key"
#define COOKIE_SIZE (16U)
#define CHALLENGE_SIZE (32U)

/*! Structure to store all allocated crypto transform key so far. */
struct key_material_handle_t store[DSEC_TA_MAX_KEY_MATERIAL_HANDLE];

/*
 * Returns a valid index to an element from the array of handle.
 */
static int32_t find_free_km_element(void)
{
    int32_t index = 0;

    index = TEE_ERROR_NO_DATA;
    for (uint32_t id = 0; id < DSEC_TA_MAX_KEY_MATERIAL_HANDLE; id++) {
        if (!store[id].initialized) {
            /*
             * Cast the size_t to a narrower type int32_t the array size cannot
             * have more than INT_MAX elements.
             */
            index = (int32_t)id;
            break;
        }
    }

    return index;
}

/*
 * Checks if a given index leads to an initialized Handle (i.e. not
 * out-of-bounds and has its boolean flag initialized set).
 */
static bool km_is_valid(int32_t index)
{
    return (index >= 0) &&
           ((uint32_t)index < DSEC_TA_MAX_KEY_MATERIAL_HANDLE) &&
           store[index].initialized;
}

static TEE_Result create_exchange_key(
    uint8_t* out_data,
    uint32_t* out_data_size,
    const uint8_t in_data1[CHALLENGE_SIZE],
    const char cookie[COOKIE_SIZE],
    const uint8_t in_data2[CHALLENGE_SIZE],
    const uint8_t* shared_secret,
    const uint32_t shared_secret_size)
{
    TEE_Result result = 0;
    int32_t dsec_result = 0;
    uint8_t tmp_data[CHALLENGE_SIZE + COOKIE_SIZE + CHALLENGE_SIZE];
    uint8_t sha256_buffer[DSEC_TA_SHA256_SIZE];

    if ((out_data != NULL) &&
        (out_data_size != NULL) &&
        (in_data1 != NULL) &&
        (cookie != NULL) &&
        (in_data2 != NULL) &&
        (shared_secret != NULL)) {

        for (uint32_t i = 0; i < *out_data_size; i++) {
            out_data[i] = 0;
        }

        TEE_MemMove(tmp_data, in_data1, CHALLENGE_SIZE);
        TEE_MemMove(&tmp_data[CHALLENGE_SIZE], cookie, COOKIE_SIZE);
        TEE_MemMove(&tmp_data[CHALLENGE_SIZE + COOKIE_SIZE],
                    in_data2,
                    CHALLENGE_SIZE);

        dsec_result = dsec_ta_digest_sha256(sha256_buffer,
                              tmp_data,
                              (CHALLENGE_SIZE + COOKIE_SIZE + CHALLENGE_SIZE));
        if (dsec_result == DSEC_SUCCESS) {

            /*
             * The sha256 is the key used for the HMAC256 of the shared secret.
             */
            result = dsec_ta_hmac_256(out_data,
                                  out_data_size,
                                  sha256_buffer,
                                  DSEC_TA_SHA256_SIZE,
                                  shared_secret,
                                  shared_secret_size);

        } else {
            result = TEE_ERROR_SECURITY;
        }

    } else {
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

static void make_unique_key_id(uint8_t key_id_out[TRANSFORMATION_KIND_SIZE])
{
    static uint32_t key_id = 0;
    uint8_t* key_id_array = (uint8_t*) &key_id;

    for (uint32_t i = 0; i < TRANSFORMATION_KIND_SIZE; i++) {
        key_id_out[i] = key_id_array[i];
    }

    key_id += 1;
}

static TEE_Result key_material_create(int* km_handle_id,
                                      bool use_gcm,
                                      bool use_256_bits)
{
    TEE_Result result = 0;
    struct key_material_t* key_material = NULL;
    const uint8_t* transformation_used = NULL;
    uint32_t generated_bytes = 16;

    const uint8_t transformation_none[] = TRANSFORMATION_KIND_NONE;

    const uint8_t transformation_aes128_gmac[] =
        TRANSFORMATION_KIND_AES128_GMAC;

    const uint8_t transformation_aes256_gmac[] =
        TRANSFORMATION_KIND_AES256_GMAC;

    const uint8_t transformation_aes128_gcm[] = TRANSFORMATION_KIND_AES128_GCM;
    const uint8_t transformation_aes256_gcm[] = TRANSFORMATION_KIND_AES256_GCM;

    if (km_handle_id != NULL) {
        *km_handle_id = find_free_km_element();
        if (*km_handle_id >= 0) {

            store[*km_handle_id].initialized = true;
            key_material = &(store[*km_handle_id].key_material);

            if (use_gcm) {
                if (use_256_bits) {
                    transformation_used = transformation_aes256_gcm;
                    generated_bytes = 32;
                } else {
                    transformation_used = transformation_aes128_gcm;
                }
            } else {
                if (use_256_bits) {
                    transformation_used = transformation_aes256_gmac;
                    generated_bytes = 32;
                } else {
                    transformation_used = transformation_aes128_gmac;
                }
            }

            TEE_MemMove(key_material->transformation_kind,
                        transformation_used,
                        TRANSFORMATION_KIND_SIZE);

            TEE_GenerateRandom(key_material->master_salt, generated_bytes);
            make_unique_key_id(key_material->sender_key_id);
            TEE_GenerateRandom(key_material->master_sender_key,
                               generated_bytes);

            TEE_MemMove(key_material->receiver_specific_key_id,
                        transformation_none,
                        RECEIVER_SPECIFIC_KEY_ID_SIZE);

            memset(key_material->master_receiver_specific_key,
                   0,
                   MASTER_RECEIVER_SPECIFIC_KEY_SIZE);

        } else {
            EMSG("Could not find a free element.\n");
            result = TEE_ERROR_OUT_OF_MEMORY;
        }

    } else {
        EMSG("Given argument is NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

static TEE_Result key_material_generate(int32_t* km_handle_id,
                                        int32_t ssh_id)
{
    struct key_material_t* key_material = NULL;

    TEE_Result result = 0;
    const struct shared_secret_handle_t* ssh = NULL;
    uint32_t master_salt_size = MASTER_SALT_SIZE;
    uint32_t master_sender_key_size = MASTER_SENDER_KEY_SIZE;
    int32_t km_handle_id_tmp = 0;
    const uint8_t transformation_aes256_gcm[] = TRANSFORMATION_KIND_AES256_GCM;

    if (km_handle_id != NULL) {
        ssh = dsec_ta_ssh_get(ssh_id);
        if (ssh != NULL) {
            km_handle_id_tmp = find_free_km_element();

            if (km_handle_id_tmp >= 0) {

                key_material = &(store[km_handle_id_tmp].key_material);

                TEE_MemMove(key_material->transformation_kind,
                            transformation_aes256_gcm,
                            TRANSFORMATION_KIND_SIZE);

                memset(key_material->sender_key_id, 0, SENDER_KEY_ID_SIZE);

                memset(key_material->receiver_specific_key_id,
                       0,
                       RECEIVER_SPECIFIC_KEY_ID_SIZE);

                memset(key_material->master_receiver_specific_key,
                       0,
                       MASTER_RECEIVER_SPECIFIC_KEY_SIZE);

                result = create_exchange_key(key_material->master_salt,
                                             &master_salt_size,
                                             ssh->challenge1_handle.data,
                                             COOKIE_SALT,
                                             ssh->challenge2_handle.data,
                                             ssh->shared_key_handle.data,
                                             ssh->shared_key_handle.data_size);

                if (result == TEE_SUCCESS) {
                    result = create_exchange_key(
                        key_material->master_sender_key,
                        &master_sender_key_size,
                        ssh->challenge2_handle.data,
                        COOKIE_KEY,
                        ssh->challenge1_handle.data,
                        ssh->shared_key_handle.data,
                        ssh->shared_key_handle.data_size);

                    if (result == TEE_SUCCESS) {
                        store[km_handle_id_tmp].initialized = true;
                        *km_handle_id = km_handle_id_tmp;
                    } else {
                        EMSG("Could not generate master key.\n");
                    }

                } else {
                    EMSG("Could not generate master salt.\n");
                }

            } else {
                EMSG("Could not find a free element.\n");
                result = TEE_ERROR_OUT_OF_MEMORY;
            }

        } else {
            EMSG("Shared Secret Handle ID %u is invalid.\n", ssh_id);
            result = TEE_ERROR_NO_DATA;
        }

    } else {
        EMSG("Given pointer is NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

static TEE_Result key_material_copy(int32_t* km_handle_id,
                                    int32_t in_km_handle_id)
{
    TEE_Result result = 0;
    int32_t km_handle_id_tmp = 0;
    struct key_material_t* out_key_material = NULL;
    const struct key_material_t* in_key_material = NULL;

    if (km_handle_id != NULL) {
        if (km_is_valid(in_km_handle_id)) {
            km_handle_id_tmp = find_free_km_element();

            if (km_handle_id_tmp >= 0) {
                out_key_material = &(store[km_handle_id_tmp].key_material);
                in_key_material = &(store[in_km_handle_id].key_material);

                TEE_MemMove(out_key_material,
                            in_key_material,
                            sizeof(*in_key_material));

                store[km_handle_id_tmp].initialized = true;
                result = TEE_SUCCESS;
            } else {
                EMSG("Could not get a free element.\n");
                result = TEE_ERROR_NO_DATA;
            }

            *km_handle_id = km_handle_id_tmp;

        } else {
            EMSG("Given key material handle %u is invalid.\n", in_km_handle_id);
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Output handle pointer is NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

static TEE_Result key_material_register(int32_t* km_handle_id,
                                        int32_t in_km_handle_id,
                                        bool is_origin_auth,
                                        bool generate_receiver_specific_key)
{
    TEE_Result result = 0;
    int32_t km_handle_id_tmp = 0;
    struct key_material_t* out_key_material = NULL;
    struct key_material_t* in_key_material = NULL;

    const uint8_t transformation_none[] = TRANSFORMATION_KIND_NONE;

    if (km_handle_id != NULL) {
        if (km_is_valid(in_km_handle_id)) {
            km_handle_id_tmp = find_free_km_element();

            if (km_handle_id_tmp >= 0) {
                out_key_material = &(store[km_handle_id_tmp].key_material);
                in_key_material = &(store[in_km_handle_id].key_material);

                TEE_MemMove(out_key_material->transformation_kind,
                            in_key_material->transformation_kind,
                            TRANSFORMATION_KIND_SIZE);

                TEE_MemMove(out_key_material->master_salt,
                            in_key_material->master_salt,
                            MASTER_SALT_SIZE);

                TEE_MemMove(out_key_material->master_sender_key,
                            in_key_material->master_sender_key,
                            MASTER_SENDER_KEY_SIZE);

                TEE_MemMove(out_key_material->sender_key_id,
                            in_key_material->sender_key_id,
                            SENDER_KEY_ID_SIZE);

                if (is_origin_auth) {
                    if (generate_receiver_specific_key) {
                        make_unique_key_id(
                            out_key_material->receiver_specific_key_id);

                        TEE_GenerateRandom(
                            out_key_material->master_receiver_specific_key,
                            MASTER_RECEIVER_SPECIFIC_KEY_SIZE);

                    } else {
                        TEE_MemMove(out_key_material->receiver_specific_key_id,
                                    in_key_material->receiver_specific_key_id,
                                    RECEIVER_SPECIFIC_KEY_ID_SIZE);

                        TEE_MemMove(out_key_material
                                        ->master_receiver_specific_key,
                                    in_key_material
                                        ->master_receiver_specific_key,
                                    MASTER_RECEIVER_SPECIFIC_KEY_SIZE);
                     }
                } else {
                    TEE_MemMove(out_key_material->receiver_specific_key_id,
                                transformation_none,
                                RECEIVER_SPECIFIC_KEY_ID_SIZE);

                    memset(out_key_material->master_receiver_specific_key,
                           0,
                           MASTER_RECEIVER_SPECIFIC_KEY_SIZE);

                }

                store[km_handle_id_tmp].initialized = true;
                *km_handle_id = km_handle_id_tmp;
                result = TEE_SUCCESS;
            } else {
                EMSG("Given key material handle %u is invalid.\n",
                     km_handle_id_tmp);

                result = TEE_ERROR_NO_DATA;
            }

        } else {
            EMSG("Given key material handle %u is invalid.\n", in_km_handle_id);
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Output handle pointer is NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_key_material_create(uint32_t parameters_type,
                                       TEE_Param parameters[2])
{
    TEE_Result result = TEE_SUCCESS;
    int32_t km_handle_id = 0;
    bool use_gcm;
    bool use_256_bits;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        use_gcm = parameters[1].value.a ? true : false;
        use_256_bits = parameters[1].value.b ? true : false;
        result = key_material_create(&km_handle_id, use_gcm, use_256_bits);
        parameters[0].value.a = km_handle_id;
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_key_material_copy(uint32_t parameters_type,
                                     TEE_Param parameters[2])
{
    TEE_Result result = TEE_SUCCESS;
    int32_t in_km_handle_id = 0;
    int32_t out_km_handle_id = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        in_km_handle_id = parameters[1].value.a;
        result = key_material_copy(&out_km_handle_id, in_km_handle_id);
        parameters[0].value.a = out_km_handle_id;
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_key_material_register(uint32_t parameters_type,
                                         TEE_Param parameters[3])
{
    TEE_Result result = TEE_SUCCESS;
    int32_t in_km_handle_id = 0;
    int32_t out_km_handle_id = 0;
    bool is_origin_auth = false;
    bool generate_receiver_specific_key = false;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        in_km_handle_id = parameters[1].value.a;
        is_origin_auth = parameters[2].value.a ? true : false;
        generate_receiver_specific_key = parameters[2].value.b ? true : false;
        result = key_material_register(&out_km_handle_id,
                                       in_km_handle_id,
                                       is_origin_auth,
                                       generate_receiver_specific_key);

        parameters[0].value.a = out_km_handle_id;
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_key_material_generate(uint32_t parameters_type,
                                         TEE_Param parameters[2])
{
    TEE_Result result = TEE_SUCCESS;
    int32_t in_ssh_id = 0;
    int32_t out_km_handle_id = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        in_ssh_id = parameters[1].value.a;
        result = key_material_generate(&out_km_handle_id, in_ssh_id);
        parameters[0].value.a = out_km_handle_id;
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_key_material_return(uint32_t parameters_type,
                                       TEE_Param parameters[4])
{
    TEE_Result result = TEE_SUCCESS;
    int32_t km_handle_id = 0;
    uint32_t key_material_part = 0;
    uint32_t output_buffer1 = 0;
    uint32_t output_buffer2 = 0;
    const struct key_material_t* key_material = NULL;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT);

    if (parameters_type == expected_types) {
        km_handle_id = parameters[2].value.a;
        if (km_is_valid(km_handle_id)) {
            key_material_part = parameters[3].value.a;
            key_material = &(store[km_handle_id].key_material);

            output_buffer1 = parameters[0].memref.size;
            output_buffer2 = parameters[1].memref.size;

            result = TEE_SUCCESS;
            switch (key_material_part) {
            case 0:
                if ((output_buffer1 >= TRANSFORMATION_KIND_SIZE) &&
                    (output_buffer2 >= MASTER_SALT_SIZE)) {

                    TEE_MemMove(parameters[0].memref.buffer,
                                key_material->transformation_kind,
                                TRANSFORMATION_KIND_SIZE);

                    parameters[0].memref.size = TRANSFORMATION_KIND_SIZE;

                    TEE_MemMove(parameters[1].memref.buffer,
                                key_material->master_salt,
                                MASTER_SALT_SIZE);

                    parameters[1].memref.size = MASTER_SALT_SIZE;
                } else {
                    result = TEE_ERROR_SHORT_BUFFER;
                }

                break;

            case 1:
                if ((output_buffer1 >= SENDER_KEY_ID_SIZE) &&
                    (output_buffer2 >= MASTER_SENDER_KEY_SIZE)) {

                    TEE_MemMove(parameters[0].memref.buffer,
                                key_material->sender_key_id,
                                SENDER_KEY_ID_SIZE);

                    parameters[0].memref.size = SENDER_KEY_ID_SIZE;

                    TEE_MemMove(parameters[1].memref.buffer,
                                key_material->master_sender_key,
                                MASTER_SENDER_KEY_SIZE);

                    parameters[1].memref.size = MASTER_SENDER_KEY_SIZE;
                } else {
                    result = TEE_ERROR_SHORT_BUFFER;
                }

                break;

            case 2:
                if ((output_buffer1 >= RECEIVER_SPECIFIC_KEY_ID_SIZE) &&
                    (output_buffer2 >= MASTER_RECEIVER_SPECIFIC_KEY_SIZE)) {

                    TEE_MemMove(parameters[0].memref.buffer,
                                key_material->receiver_specific_key_id,
                                RECEIVER_SPECIFIC_KEY_ID_SIZE);

                    parameters[0].memref.size = RECEIVER_SPECIFIC_KEY_ID_SIZE;

                    TEE_MemMove(parameters[1].memref.buffer,
                                key_material->master_receiver_specific_key,
                                MASTER_RECEIVER_SPECIFIC_KEY_SIZE);

                    parameters[1].memref.size =
                        MASTER_RECEIVER_SPECIFIC_KEY_SIZE;
                }

                break;

            default:
                break;
            }

        } else {
            EMSG("Given handle ID: 0x%x is invalid.\n", km_handle_id);
            result = TEE_ERROR_NO_DATA;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_key_material_delete(uint32_t parameters_type,
                                       TEE_Param parameters[1])
{
    TEE_Result result = TEE_SUCCESS;

    int32_t km_handle_id = 0;
    struct key_material_handle_t* km_handle = NULL;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        km_handle_id = (int32_t)parameters[0].value.a;

        if (km_is_valid(km_handle_id)) {
            km_handle = &(store[km_handle_id]);

            memset(&(km_handle->key_material),
                   0,
                   sizeof(km_handle->key_material));

            km_handle->initialized = false;

        } else {
            EMSG("Requested handle %d is uninitialized or out-of-bounds.\n",
                 km_handle_id);

            result = TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
