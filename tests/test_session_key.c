/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_session_key.h>
#include <dsec_key_material.h>
#include <dsec_errno.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <string.h>

static void test_case_session_key_create(void)
{
    int32_t result = 0;
    int32_t km_handle_id = 0;
    uint8_t session_key[32] = {0};

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_session_key_create_and_get(session_key,
                                             &instance,
                                             km_handle_id,
                                             0,
                                             false);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    const int POSSIBLE_STATES = 2;
    const int NUMBER_OF_SETS = 3;
    const int NUMBER_OF_PERMUTATIONS = (POSSIBLE_STATES<<NUMBER_OF_SETS);

    for (int32_t i = 0; i < NUMBER_OF_PERMUTATIONS; i++) {
        bool use_gmac = ((i % 2) == 0);    /* 0, 1, 0, 1, 0, 1, 0, 1 */
        bool use_256_bits = ((i % 4) < 2); /* 1, 1, 0, 0, 1, 1, 0, 0 */
        bool receiver_specific = (i < 4);  /* 1, 1, 1, 1, 0, 0, 0, 0 */
        uint32_t session_id = i * 10;

        result = dsec_key_material_create(&km_handle_id,
                                          &instance,
                                          use_gmac,
                                          use_256_bits);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

        result = dsec_session_key_create_and_get(session_key,
                                                 &instance,
                                                 km_handle_id,
                                                 session_id,
                                                 receiver_specific);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        result = dsec_key_material_delete(&instance, km_handle_id);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_session_key_create_bad_parameters(void)
{
    int32_t result = 0;
    int32_t km_handle_id = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    /* NULL session key */
    result = dsec_session_key_create_and_get(NULL,
                                             &instance,
                                             km_handle_id,
                                             0,
                                             false);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL session key */
    result = dsec_key_material_create(NULL,
                                      &instance,
                                      true,
                                      true);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_session_key_delete_miss(void)
{
    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    /* Unused session key */
    int result = dsec_key_material_delete(&instance, 0);
    DSEC_TEST_ASSERT(result != DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_session_key_encrypt(void)
{
    int32_t result = 0;
    int32_t km_handle_id = 0;

    int32_t session_handle_id = 0;

    uint8_t key_data[] = {
        0x0b, 0x81, 0xcd, 0x35, 0x56, 0x1c, 0xce, 0xe0, 0x71, 0x11, 0x1b, 0x72,
        0xd0, 0x76, 0x2b, 0x17, 0x4b, 0x8b, 0x29, 0x8b, 0x6f, 0x9d, 0xa8, 0x30,
        0x69, 0x45, 0xd2, 0xc9, 0xd3, 0xc8, 0x89, 0x49};

    uint32_t key_data_size = sizeof(key_data);

    uint8_t data_in[100] = {1};
    uint8_t data_in2[100] = {1};
    uint32_t data_in_size = 100;

    uint8_t data_out[100] = {1};
    uint8_t data_out2[100] = {1};
    uint32_t data_out_size = 100;

    uint8_t data_decrypt_out[sizeof(data_in)] = {1};
    uint32_t data_decrypt_out_size = data_in_size;

    uint8_t iv[] = {0xfe, 0xd2, 0x28, 0x3a, 0xfc, 0x26, 0xa1, 0x85, 0x29, 0x80,
                    0xae, 0x92};

    uint8_t iv2[] = {0xfe, 0xd2, 0x28, 0x3a, 0xfc, 0x26, 0xa1, 0x85, 0x29, 0x80,
                    0xae, 0x92};

    uint32_t iv_size = sizeof(iv);

    uint8_t tag[16] = {1};
    uint8_t tag2[16] = {1};
    uint32_t tag_size = sizeof(tag);

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    const int POSSIBLE_STATES = 2;
    const int NUMBER_OF_SETS = 3;
    const int NUMBER_OF_PERMUTATIONS = (POSSIBLE_STATES<<NUMBER_OF_SETS);

    for (int32_t i = 0; i < NUMBER_OF_PERMUTATIONS; i++) {
        bool use_gmac = ((i % 2) == 0);    /* 0, 1, 0, 1, 0, 1, 0, 1 */
        bool use_256_bits = ((i % 4) < 2); /* 1, 1, 0, 0, 1, 1, 0, 0 */
        bool receiver_specific = (i < 4);  /* 1, 1, 1, 1, 0, 0, 0, 0 */
        uint32_t session_id = i * 10;

        result = dsec_key_material_create(&km_handle_id,
                                          &instance,
                                          use_gmac,
                                          use_256_bits);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

        result = dsec_session_key_create(&session_handle_id,
                                         &instance,
                                         km_handle_id,
                                         session_id,
                                         receiver_specific);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

        result = dsec_session_key_encrypt(data_out,
                                          &data_out_size,
                                          tag,
                                          &tag_size,
                                          &instance,
                                          session_handle_id,
                                          key_data_size,
                                          data_in,
                                          data_in_size,
                                          iv,
                                          iv_size);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(data_out_size > 0);

        /* Check that the input isn't clobbered */
        DSEC_TEST_ASSERT(memcmp(data_in2, data_in, data_in_size) == 0);
        DSEC_TEST_ASSERT(memcmp(iv2, iv, iv_size) == 0);

        /* Check that the buffer isn't unchanged */
        DSEC_TEST_ASSERT(memcmp(data_in2,
                                data_out,
                                (data_out_size < data_in_size ?
                                 data_out_size : data_in_size)) != 0);

        memmove((uint8_t*)data_out2, (uint8_t*)data_out, data_out_size);
        memmove((uint8_t*)tag2, (uint8_t*)tag, tag_size);

        result = dsec_session_key_decrypt(data_decrypt_out,
                                          &data_decrypt_out_size,
                                          &instance,
                                          tag,
                                          tag_size,
                                          session_handle_id,
                                          key_data_size,
                                          data_out, /* data from encryption */
                                          data_out_size,
                                          iv,
                                          iv_size);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(data_decrypt_out_size > 0);
        DSEC_TEST_ASSERT(data_in_size == data_decrypt_out_size);

        /* Check that the input isn't clobbered */
        DSEC_TEST_ASSERT(memcmp(data_out2, data_out, data_out_size) == 0);
        DSEC_TEST_ASSERT(memcmp(iv2, iv, iv_size) == 0);
        DSEC_TEST_ASSERT(memcmp(tag2, tag, tag_size) == 0);

        /* Check that the buffer isn't unchanged */
        DSEC_TEST_ASSERT(memcmp(data_out2,
                                data_decrypt_out,
                                (data_decrypt_out_size < data_out_size ?
                                 data_decrypt_out_size : data_out_size)) != 0);

        /* Check that decrypt(encrypt(data)) == data */
        DSEC_TEST_ASSERT(memcmp((uint8_t*)data_in,
                                (uint8_t*)data_decrypt_out,
                                data_decrypt_out_size) == 0);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_session_key_encrypt_bad_parameters(void)
{
    int32_t result = 0;
    int32_t km_handle_id = 0;

    int32_t session_handle_id = 0;

    uint8_t data_out[100] = {0};
    uint32_t data_out_size = sizeof(data_out);

    uint32_t key_data_size = 16 /* 128 bits */;

    uint8_t data_in[] = {
        0x15, 0x03, 0x34, 0x00, 0x00, 0x00, 0x10, 0x00, 0xff, 0x00, 0x03, 0xc7,
        0xff, 0x00, 0x03, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x70, 0x00, 0x10, 0x00, 0xeb, 0xba, 0x3f, 0x10, 0xa7, 0x26, 0x5e, 0x06,
        0xc1, 0x05, 0x96, 0x5d, 0x00, 0x00, 0x01, 0x03, 0x71, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00};

    const uint32_t data_in_size = sizeof(data_in);

    uint8_t data_decrypt_out[sizeof(data_in)] = {0};
    uint32_t data_decrypt_out_size = data_in_size;

    uint8_t iv[] = {
        0x0e, 0xcf, 0xf7, 0x03, 0x2b, 0x67, 0x0b, 0xa0, 0x1e, 0x46, 0x77, 0x31};

    uint32_t iv_size = sizeof(iv);

    /* Maximum size of a MAC for AES-GCM */
    uint8_t tag[16] = {0};
    uint32_t tag_size = sizeof(tag);

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_key_material_create(&km_handle_id,
                                      &instance,
                                      true,
                                      true);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_session_key_create(&session_handle_id,
                                     &instance,
                                     km_handle_id,
                                     0,
                                     true);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* NULL output_data */
    result = dsec_session_key_encrypt(NULL,
                                      &data_out_size,
                                      tag,
                                      &tag_size,
                                      &instance,
                                      session_handle_id,
                                      key_data_size,
                                      data_in,
                                      data_in_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL tag */
    result = dsec_session_key_encrypt(data_out,
                                      &data_out_size,
                                      NULL,
                                      &tag_size,
                                      &instance,
                                      session_handle_id,
                                      key_data_size,
                                      data_in,
                                      data_in_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL data_in */
    result = dsec_session_key_encrypt(data_out,
                                      &data_out_size,
                                      tag,
                                      &tag_size,
                                      &instance,
                                      session_handle_id,
                                      key_data_size,
                                      NULL,
                                      data_in_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL iv */
    result = dsec_session_key_encrypt(data_out,
                                      &data_out_size,
                                      tag,
                                      &tag_size,
                                      &instance,
                                      session_handle_id,
                                      key_data_size,
                                      data_in,
                                      data_in_size,
                                      NULL,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    uint32_t bad_size = 0;

    /* Zero-sized data_out */
    result = dsec_session_key_encrypt(data_out,
                                      &bad_size,
                                      tag,
                                      &tag_size,
                                      &instance,
                                      session_handle_id,
                                      key_data_size,
                                      data_in,
                                      data_in_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    bad_size = 0;

    /* Zero-sized tag */
    result = dsec_session_key_encrypt(data_out,
                                      &data_out_size,
                                      tag,
                                      &bad_size,
                                      &instance,
                                      session_handle_id,
                                      key_data_size,
                                      data_in,
                                      data_in_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    bad_size = 0;

    /* Zero-sized key_data */
    result = dsec_session_key_encrypt(data_out,
                                      &data_out_size,
                                      tag,
                                      &tag_size,
                                      &instance,
                                      session_handle_id,
                                      bad_size,
                                      data_in,
                                      data_in_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Zero-sized data_in */
    result = dsec_session_key_encrypt(data_out,
                                      &data_out_size,
                                      tag,
                                      &tag_size,
                                      &instance,
                                      session_handle_id,
                                      key_data_size,
                                      data_in,
                                      bad_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Zero-sized iv */
    result = dsec_session_key_encrypt(data_out,
                                      &data_out_size,
                                      tag,
                                      &tag_size,
                                      &instance,
                                      session_handle_id,
                                      key_data_size,
                                      data_in,
                                      data_in_size,
                                      iv,
                                      bad_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL data_out */
    result = dsec_session_key_decrypt(NULL,
                                      &data_decrypt_out_size,
                                      &instance,
                                      tag,
                                      tag_size,
                                      session_handle_id,
                                      key_data_size,
                                      data_out,
                                      data_out_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL tag */
    result = dsec_session_key_decrypt(data_decrypt_out,
                                      &data_decrypt_out_size,
                                      &instance,
                                      NULL,
                                      tag_size,
                                      session_handle_id,
                                      key_data_size,
                                      data_out,
                                      data_out_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL data_in */
    result = dsec_session_key_decrypt(data_decrypt_out,
                                      &data_decrypt_out_size,
                                      &instance,
                                      tag,
                                      tag_size,
                                      session_handle_id,
                                      key_data_size,
                                      NULL,
                                      data_out_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL iv */
    result = dsec_session_key_decrypt(data_decrypt_out,
                                      &data_decrypt_out_size,
                                      &instance,
                                      tag,
                                      tag_size,
                                      session_handle_id,
                                      key_data_size,
                                      data_out,
                                      data_out_size,
                                      NULL,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Zero-sized data_out */
    result = dsec_session_key_decrypt(data_decrypt_out,
                                      &bad_size,
                                      &instance,
                                      tag,
                                      tag_size,
                                      session_handle_id,
                                      key_data_size,
                                      data_out,
                                      data_out_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    bad_size = 0;

    /* Zero-sized tag */
    result = dsec_session_key_decrypt(data_decrypt_out,
                                      &data_decrypt_out_size,
                                      &instance,
                                      tag,
                                      bad_size,
                                      session_handle_id,
                                      key_data_size,
                                      data_out,
                                      data_out_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Zero-sized key_data */
    result = dsec_session_key_decrypt(data_decrypt_out,
                                      &data_decrypt_out_size,
                                      &instance,
                                      tag,
                                      tag_size,
                                      session_handle_id,
                                      bad_size,
                                      data_out,
                                      data_out_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Zero-sized data_in */
    result = dsec_session_key_decrypt(data_decrypt_out,
                                      &data_decrypt_out_size,
                                      &instance,
                                      tag,
                                      tag_size,
                                      session_handle_id,
                                      key_data_size,
                                      data_out,
                                      bad_size,
                                      iv,
                                      iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Zero-sized iv */
    result = dsec_session_key_decrypt(data_decrypt_out,
                                      &data_decrypt_out_size,
                                      &instance,
                                      tag,
                                      tag_size,
                                      session_handle_id,
                                      key_data_size,
                                      data_out,
                                      data_out_size,
                                      iv,
                                      bad_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_session_key_create),
    DSEC_TEST_CASE(test_case_session_key_create_bad_parameters),
    DSEC_TEST_CASE(test_case_session_key_delete_miss),
    DSEC_TEST_CASE(test_case_session_key_encrypt),
    DSEC_TEST_CASE(test_case_session_key_encrypt_bad_parameters),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Session key tests",
    .test_case_count = sizeof(test_case_table)/sizeof(test_case_table[0]),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
