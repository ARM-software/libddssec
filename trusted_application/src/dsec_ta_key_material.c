/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
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
static struct key_material_handle_t store[DSEC_TA_MAX_KEY_MATERIAL_HANDLE];

/*
 * Sets *output_index to a valid element from the array of handles.
 */
static int32_t find_free_km_element(uint32_t* output_index)
{
    int32_t result = TEE_ERROR_NO_DATA;

    if (output_index != NULL) {
        for (uint32_t id = 0; id < DSEC_TA_MAX_KEY_MATERIAL_HANDLE; id++) {
            if (!store[id].initialized) {
                *output_index = id;
                result = DSEC_SUCCESS;
                break;
            }
        }
    }

    return result;
}

/*
 * Checks if a given index leads to an initialized Handle.
 */
static bool km_is_valid(uint32_t index)
{
    return (index < DSEC_TA_MAX_KEY_MATERIAL_HANDLE) &&
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

static TEE_Result key_material_create(uint32_t* km_handle_id,
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
        result = find_free_km_element(km_handle_id);
        if (result == DSEC_SUCCESS) {
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
            EMSG("Can't find a free km element. Error is %d", result);
            result = TEE_ERROR_OUT_OF_MEMORY;
        }
    } else {
        EMSG("Given argument is NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

static TEE_Result key_material_generate(uint32_t* km_handle_id,
                                        int32_t ssh_id)
{
    struct key_material_t* key_material = NULL;

    TEE_Result result = 0;
    const struct shared_secret_handle_t* ssh = NULL;
    uint32_t master_salt_size = MASTER_SALT_SIZE;
    uint32_t master_sender_key_size = MASTER_SENDER_KEY_SIZE;
    const uint8_t transformation_aes256_gcm[] = TRANSFORMATION_KIND_AES256_GCM;

    if (km_handle_id != NULL) {
        ssh = dsec_ta_ssh_get(ssh_id);
        if (ssh != NULL) {
            result = find_free_km_element(km_handle_id);
            if (result == DSEC_SUCCESS) {
                key_material = &(store[*km_handle_id].key_material);

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
                        store[*km_handle_id].initialized = true;
                    } else {
                        EMSG("Could not generate master key.\n");
                    }

                } else {
                    EMSG("Could not generate master salt.\n");
                }

            } else {
                EMSG("Could not find a free element. Error is %d", result);
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

static TEE_Result key_material_copy(uint32_t* km_handle_id,
                                    uint32_t in_km_handle_id)
{
    TEE_Result result = 0;
    struct key_material_t* out_key_material = NULL;
    const struct key_material_t* in_key_material = NULL;

    if (km_handle_id != NULL) {
        if (km_is_valid(in_km_handle_id)) {
            result = find_free_km_element(km_handle_id);
            if (result == DSEC_SUCCESS) {
                out_key_material = &(store[*km_handle_id].key_material);
                in_key_material = &(store[in_km_handle_id].key_material);

                TEE_MemMove(out_key_material,
                            in_key_material,
                            sizeof(*in_key_material));

                store[*km_handle_id].initialized = true;
                result = TEE_SUCCESS;
            } else {
                EMSG("Could not get a free element. Error is %d", result);
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

static TEE_Result key_material_register(uint32_t* km_handle_id,
                                        uint32_t in_km_handle_id,
                                        bool is_origin_auth,
                                        bool generate_receiver_specific_key)
{
    TEE_Result result = 0;
    struct key_material_t* out_key_material = NULL;
    struct key_material_t* in_key_material = NULL;

    const uint8_t transformation_none[] = TRANSFORMATION_KIND_NONE;

    if (km_handle_id != NULL) {
        if (km_is_valid(in_km_handle_id)) {
            result = find_free_km_element(km_handle_id);
            if (result == DSEC_SUCCESS) {
                out_key_material = &(store[*km_handle_id].key_material);
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

                        TEE_MemMove(
                            out_key_material->master_receiver_specific_key,
                            in_key_material->master_receiver_specific_key,
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

                store[*km_handle_id].initialized = true;
                result = TEE_SUCCESS;
            } else {
                EMSG("Given key material handle %u is invalid. Error is %d",
                     in_km_handle_id,
                     result);

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

static TEE_Result key_material_serialize(uint8_t* output,
                                         uint32_t* output_size,
                                         uint32_t in_km_handle_id)
{
    TEE_Result result = 0;
    struct key_material_t* in_key_material = NULL;
    uint8_t* output_tmp = NULL;
    uint8_t kind = 0;
    uint8_t key_len = 0;
    uint8_t has_specific_key = 0;

    if ((output != NULL) && (output_size != NULL)) {

        if (km_is_valid(in_km_handle_id)) {
            in_key_material = &(store[in_km_handle_id].key_material);

            output_tmp = output;
            *output_size = 0;

            memcpy(output,
                   in_key_material->transformation_kind,
                   TRANSFORMATION_KIND_SIZE);

            output_tmp += TRANSFORMATION_KIND_SIZE;
            *output_size += TRANSFORMATION_KIND_SIZE;

            kind = in_key_material->transformation_kind[3];
            if (kind == 0) {
                /*
                 * transformation_kind = {0, 0, 0, 0}: (NONE)
                 * Need to set:
                 *  - master_salt {0, 0, 0, 0}
                 *  - sender_key_id {0, 0, 0, 0}
                 *  - master_sender_key {0, 0, 0, 0}
                 *  - receiver_specific_key_id {0, 0, 0, 0}
                 *  - master_receiver_specific_key {0, 0, 0, 0}
                 *
                 * Which is 40 bytes to 0
                 */
                memset(output_tmp, 0, 40);
                *output_size += 40;

            } else {
                /*
                 * AES128 for kinds 1 and 2: 16 bytes
                 * AES256 for kinds 3 and 4: 32 bytes
                 */
                key_len = (kind <= 2) ? 16 : 32;

                /*
                 * Copy {0 0 0 key_len}
                 */
                memset(output_tmp, 0, 3);
                output_tmp += 3;
                *output_tmp = key_len;
                output_tmp += 1;
                *output_size += 4;

                memcpy(output_tmp,
                       in_key_material->master_salt,
                       key_len);

                output_tmp += key_len;
                *output_size += key_len;

                memcpy(output_tmp,
                       in_key_material->sender_key_id,
                       SENDER_KEY_ID_SIZE);

                output_tmp += SENDER_KEY_ID_SIZE;
                *output_size += SENDER_KEY_ID_SIZE;

                /*
                 * Copy {0 0 0 key_len}
                 */
                memset(output_tmp, 0, 3);
                output_tmp += 3;
                *output_tmp = key_len;
                output_tmp += 1;

                memcpy(output_tmp,
                       in_key_material->master_sender_key,
                       key_len);

                output_tmp += key_len;
                *output_size += key_len;

                has_specific_key = 0;
                for (uint32_t i = 0; i < RECEIVER_SPECIFIC_KEY_ID_SIZE; i++) {
                    output_tmp[0] =
                        in_key_material->receiver_specific_key_id[i];

                    has_specific_key |= output_tmp[0];
                    output_tmp++;
                }

                *output_size += RECEIVER_SPECIFIC_KEY_ID_SIZE;

                if (has_specific_key == 0) {
                    memset(output_tmp, 0, 4);
                    output_tmp += 4;
                    *output_size += 4;
                } else {
                    /*
                     * Copy {0 0 0 key_len}
                     */
                    memset(output_tmp, 0, 3);
                    output_tmp += 3;
                    *output_tmp = key_len;
                    output_tmp += 1;
                    *output_size += 4;

                    memcpy(output_tmp,
                           in_key_material->master_receiver_specific_key,
                           key_len);

                    *output_size += key_len;
                }

                result = TEE_SUCCESS;
            }

        } else {
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

static TEE_Result key_material_deserialize(uint32_t* km_handle_id,
                                           const uint8_t* input,
                                           uint32_t input_size)
{
    TEE_Result result = 0;
    struct key_material_t* out_key_material = NULL;
    uint8_t kind = 0;
    uint32_t position = 0;
    uint8_t key_len = 0;
    uint8_t has_specific_key = 0;

    if (km_handle_id != NULL) {
        result = find_free_km_element(km_handle_id);
        if (result == DSEC_SUCCESS) {
            out_key_material = &(store[*km_handle_id].key_material);
            store[*km_handle_id].initialized = true;

            result = TEE_SUCCESS;

            kind = input[3];
            out_key_material->transformation_kind[0] = input[0];
            out_key_material->transformation_kind[1] = input[1];
            out_key_material->transformation_kind[2] = input[2];
            out_key_material->transformation_kind[3] = kind;
            if (kind == 0) {
                memset(out_key_material->sender_key_id, 0, SENDER_KEY_ID_SIZE);
                memset(out_key_material->receiver_specific_key_id,
                       0,
                       RECEIVER_SPECIFIC_KEY_ID_SIZE);

                memset(out_key_material->master_salt, 0, MASTER_SALT_SIZE);
                memset(out_key_material->master_sender_key,
                       0,
                       MASTER_SENDER_KEY_SIZE);

                memset(out_key_material->master_receiver_specific_key,
                       0,
                       MASTER_RECEIVER_SPECIFIC_KEY_SIZE);

            } else {
                /* Get key length. */
                position = 4 /* {0, 0, 0, 0} */ + 3 /* {0, 0, 0} */;
                key_len = input[position];
                position += 1;

                /* Make sure key length is valid. */
                if ((key_len == 16) || (key_len == 32)) {
                    memcpy(out_key_material->master_salt,
                           &input[position],
                           key_len);

                    position += key_len;

                    memcpy(out_key_material->sender_key_id,
                           &input[position],
                           SENDER_KEY_ID_SIZE);

                    position += SENDER_KEY_ID_SIZE;

                    position += 3 /* {0, 0, 0} */;
                    key_len = input[position];
                    position += 1;
                    if ((key_len == 16) || (key_len == 32)) {
                        memcpy(out_key_material->master_sender_key,
                               &input[position],
                               key_len);

                        position += key_len;

                        has_specific_key = 0;
                        for (uint8_t i = 0;
                             i < RECEIVER_SPECIFIC_KEY_ID_SIZE;
                             i++) {

                            out_key_material->receiver_specific_key_id[i] =
                                input[position];

                            has_specific_key |= input[position];
                            position += 1;
                        }

                        if (has_specific_key != 0) {
                            position += 3 /* {0, 0, 0} */;
                            key_len = input[position];
                            if ((key_len == 16) || (key_len == 32)) {
                                position += 1;

                                memcpy(
                                out_key_material->master_receiver_specific_key,
                                &input[position],
                                key_len);

                            } else {
                                result = TEE_ERROR_BAD_PARAMETERS;
                            }
                        }

                    } else {
                        result = TEE_ERROR_BAD_PARAMETERS;
                    }
                } else {
                    result = TEE_ERROR_BAD_PARAMETERS;
                }
            }
        } else {
            EMSG("Can't find a free km element. Error is %d", result);
            result = TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_key_material_create(uint32_t parameters_type,
                                       TEE_Param parameters[2])
{
    TEE_Result result = TEE_SUCCESS;
    uint32_t km_handle_id = 0;
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
    uint32_t in_km_handle_id = 0;
    uint32_t out_km_handle_id = 0;

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
    uint32_t in_km_handle_id = 0;
    uint32_t out_km_handle_id = 0;
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
    uint32_t out_km_handle_id = 0;

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

static TEE_Result key_material_remove_sender_key_id(uint32_t km_handle_id)
{
    TEE_Result result = TEE_SUCCESS;
    if (km_handle_id < DSEC_TA_MAX_KEY_MATERIAL_HANDLE) {
        if (store[km_handle_id].initialized) {
            memset(store[km_handle_id].key_material.sender_key_id,
                   0,
                   SENDER_KEY_ID_SIZE);
        } else {
            EMSG("Key material handle not initialized");
            result = TEE_ERROR_NO_DATA;
        }
    } else {
        EMSG("Bad parameters types");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_key_material_return(uint32_t parameters_type,
                                       TEE_Param parameters[4])
{
    TEE_Result result = TEE_SUCCESS;
    uint32_t km_handle_id = 0;
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
                if (output_buffer1 >= TRANSFORMATION_KIND_SIZE) {
                    TEE_MemMove(parameters[0].memref.buffer,
                                key_material->transformation_kind,
                                TRANSFORMATION_KIND_SIZE);

                    parameters[0].memref.size = TRANSFORMATION_KIND_SIZE;

                }

                if (output_buffer2 >= MASTER_SALT_SIZE) {
                    TEE_MemMove(parameters[1].memref.buffer,
                                key_material->master_salt,
                                MASTER_SALT_SIZE);

                    parameters[1].memref.size = MASTER_SALT_SIZE;
                }

                break;

            case 1:
                if (output_buffer1 >= SENDER_KEY_ID_SIZE) {
                    TEE_MemMove(parameters[0].memref.buffer,
                                key_material->sender_key_id,
                                SENDER_KEY_ID_SIZE);

                    parameters[0].memref.size = SENDER_KEY_ID_SIZE;

                }

                if (output_buffer2 >= MASTER_SENDER_KEY_SIZE) {
                    TEE_MemMove(parameters[1].memref.buffer,
                                key_material->master_sender_key,
                                MASTER_SENDER_KEY_SIZE);

                    parameters[1].memref.size = MASTER_SENDER_KEY_SIZE;
                }

                break;

            case 2:
                if (output_buffer1 >= RECEIVER_SPECIFIC_KEY_ID_SIZE) {

                    TEE_MemMove(parameters[0].memref.buffer,
                                key_material->receiver_specific_key_id,
                                RECEIVER_SPECIFIC_KEY_ID_SIZE);

                    parameters[0].memref.size = RECEIVER_SPECIFIC_KEY_ID_SIZE;
                }

                if (output_buffer2 >= MASTER_RECEIVER_SPECIFIC_KEY_SIZE) {
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

    uint32_t km_handle_id = 0;
    struct key_material_handle_t* km_handle = NULL;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        km_handle_id = parameters[0].value.a;

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

TEE_Result dsec_ta_key_material_serialize(uint32_t parameters_type,
                                          TEE_Param parameters[2])
{
    TEE_Result result = TEE_SUCCESS;

    uint32_t km_handle_id = 0;
    uint8_t* output = 0;
    uint32_t output_size = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        km_handle_id = parameters[1].value.a;
        output = parameters[0].memref.buffer;
        output_size = parameters[0].memref.size;

        result = key_material_serialize(output,
                                        &output_size,
                                        km_handle_id);

        if (result == TEE_SUCCESS) {
            parameters[0].memref.size = output_size;
        } else {
            parameters[0].memref.size = 0;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_key_material_remove_sender_key_id(
    uint32_t parameters_type,
    TEE_Param parameters[1])
{
    TEE_Result result = TEE_SUCCESS;
    uint32_t km_handle_id = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        km_handle_id = parameters[0].value.a;
        result = key_material_remove_sender_key_id(km_handle_id);
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_key_material_deserialize(uint32_t parameters_type,
                                            TEE_Param parameters[2])
{
    TEE_Result result = TEE_SUCCESS;

    uint32_t km_handle_id = 0;
    uint8_t* input = 0;
    uint32_t input_size = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_MEMREF_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        input = parameters[1].memref.buffer;
        input_size = parameters[1].memref.size;

        result = key_material_deserialize(&km_handle_id,
                                          input,
                                          input_size);

        if (result == TEE_SUCCESS) {
            parameters[0].value.a = km_handle_id;
        } else {
            parameters[0].value.a = -1;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

struct key_material_t* key_material_get(uint32_t km_handle_id)
{
    struct key_material_t* km = NULL;

    if (km_is_valid(km_handle_id)) {
        store[km_handle_id].initialized = true;
        km = &(store[km_handle_id].key_material);
    }

    return km;
}
