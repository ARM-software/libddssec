/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_aes.h>
#include <dsec_errno.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <stdlib.h>
#include <string.h>

#define MAX_UDP_BUFFER_BYTES 65527

static void test_case_aes_256(void)
{
    int32_t result = 0;

    uint8_t data_out[220] = {1};
    uint32_t data_out_size = sizeof(data_out);

    uint8_t key_data[] = {
        0x0b, 0x81, 0xcd, 0x35, 0x56, 0x1c, 0xce, 0xe0, 0x71, 0x11, 0x1b, 0x72,
        0xd0, 0x76, 0x2b, 0x17, 0x4b, 0x8b, 0x29, 0x8b, 0x6f, 0x9d, 0xa8, 0x30,
        0x69, 0x45, 0xd2, 0xc9, 0xd3, 0xc8, 0x89, 0x49};

    uint32_t key_data_size = sizeof(key_data);

    uint8_t data_in[] = {
        0x0c, 0x01, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x01, 0x0f,
        0xeb, 0xba, 0x3f, 0x10, 0xa7, 0x26, 0x5e, 0x06, 0xc1, 0x05, 0x96, 0x5d,
        0x0e, 0x01, 0x0c, 0x00, 0xa6, 0xb1, 0xa0, 0x7e, 0x9c, 0x49, 0x9f, 0x45,
        0x3b, 0x68, 0x33, 0xad, 0x31, 0x01, 0x14, 0x00, 0x00, 0x00, 0x00, 0x02,
        0xa7, 0x51, 0x4f, 0xb7, 0x0e, 0xcf, 0xf7, 0x03, 0x21, 0x07, 0xa2, 0xbd,
        0xae, 0x54, 0xfe, 0xef, 0x30, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x0c,
        0xb6, 0xb5, 0x5f, 0x18, 0x26, 0xb0, 0x1d, 0x1c, 0x10, 0x60, 0x37, 0xc0,
        0x32, 0x01, 0x14, 0x00, 0xa2, 0x5a, 0xfd, 0x1e, 0xa7, 0x35, 0xd3, 0x57,
        0x9e, 0x93, 0xb2, 0xe6, 0x5a, 0x65, 0x1d, 0xb0, 0x00, 0x00, 0x00, 0x00,
        0x31, 0x01, 0x14, 0x00, 0x00, 0x00, 0x00, 0x02, 0xa7, 0x51, 0x4f, 0xb7,
        0x0e, 0xcf, 0xf7, 0x03, 0x2b, 0x67, 0x0b, 0xa0, 0x1e, 0x46, 0x77, 0x31,
        0x30, 0x01, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x38, 0x7d, 0x6e, 0x13, 0xc7,
        0xd6, 0xac, 0x85, 0x26, 0x76, 0xc2, 0x4c, 0xdf, 0x6d, 0x13, 0x49, 0xc9,
        0x04, 0x69, 0x26, 0x55, 0xe2, 0x1b, 0x91, 0xae, 0xee, 0x01, 0x50, 0xed,
        0x05, 0x43, 0xfa, 0xb8, 0xe9, 0xf6, 0xa4, 0x67, 0x26, 0x8b, 0xb2, 0x49,
        0x18, 0x19, 0x7c, 0xc5, 0x4f, 0x8f, 0x21, 0x39, 0xaf, 0x91, 0xdb, 0x8d,
        0x29, 0x8b, 0x28, 0x65, 0x32, 0x01, 0x14, 0x00, 0x80, 0xf6, 0xe8, 0xe6,
        0x47, 0x03, 0xea, 0x9b, 0x2d, 0x03, 0x8b, 0x67, 0x7d, 0x6b, 0x83, 0xcf,
        0x00, 0x00, 0x00, 0x00};

    uint32_t data_in_size = sizeof(data_in);
    uint8_t iv[] = {0xfe, 0xd2, 0x28, 0x3a, 0xfc, 0x26, 0xa1, 0x85, 0x29, 0x80,
                    0xae, 0x92};

    uint32_t iv_size = sizeof(iv);

    uint8_t tag[16] = {1};
    uint32_t tag_size = sizeof(tag);

    uint8_t expected_data_out[] = {
        0xf3, 0xce, 0x09, 0x4c, 0xb6, 0xab, 0xf4, 0x3a, 0x1b, 0x10, 0xb2, 0x9c,
        0x78, 0x0a, 0xee, 0xac, 0x7e, 0x9e, 0x08, 0x7c, 0x62, 0x2f, 0x5d, 0xfd,
        0xf4, 0x34, 0x63, 0x0e, 0x03, 0x56, 0x78, 0xe5, 0x06, 0x79, 0x67, 0xf0,
        0xcb, 0x17, 0xf5, 0xd8, 0xcf, 0xa9, 0xc7, 0xd3, 0xea, 0xff, 0x9c, 0x60,
        0x34, 0xd1, 0x48, 0xda, 0x83, 0xec, 0x16, 0x10, 0x70, 0xdc, 0xa6, 0x87,
        0xdf, 0x04, 0xd2, 0xa3, 0x8b, 0xe0, 0xb3, 0x4b, 0x99, 0x78, 0xb9, 0x33,
        0x97, 0x5c, 0x7b, 0xe1, 0x54, 0x6f, 0xa5, 0xd1, 0x35, 0x7e, 0xfa, 0x3d,
        0x94, 0xed, 0xfd, 0xc8, 0x83, 0x87, 0xd8, 0x13, 0xf8, 0xb0, 0xef, 0xd3,
        0x03, 0xf8, 0x3b, 0xd8, 0x18, 0x22, 0xc9, 0x2c, 0x92, 0x2b, 0xe2, 0x2a,
        0xc7, 0x5e, 0xcd, 0xfd, 0x18, 0x75, 0x48, 0x6d, 0x05, 0x94, 0x0d, 0x1f,
        0x25, 0xad, 0x3f, 0x8a, 0xc7, 0x09, 0x31, 0x1b, 0xec, 0xec, 0x6f, 0x3e,
        0xd8, 0xd9, 0x27, 0x18, 0xa5, 0x50, 0x5a, 0x8a, 0xce, 0xfd, 0x27, 0x9a,
        0x1d, 0xcf, 0x15, 0xce, 0x38, 0xf0, 0xa1, 0x50, 0xc7, 0xa4, 0x5c, 0x79,
        0xb4, 0xf4, 0x3b, 0x8e, 0x6f, 0xf3, 0xe3, 0xaf, 0x3d, 0x9a, 0x34, 0xec,
        0x9a, 0xdd, 0x7c, 0xc1, 0xb9, 0xf0, 0x7e, 0x61, 0xa1, 0xba, 0x33, 0xe1,
        0x7b, 0x18, 0xae, 0x46, 0x0c, 0x54, 0x15, 0xde, 0x43, 0xb7, 0xc8, 0x82,
        0x34, 0x17, 0x1d, 0x50, 0x62, 0xd0, 0x8f, 0x3a, 0x42, 0xa8, 0x4c, 0xb4,
        0xc5, 0xdb, 0x9a, 0x85, 0x37, 0x96, 0xc3, 0xd1, 0x6b, 0x6a, 0xbb, 0xe2,
        0xac, 0xb8, 0x5b, 0x0e};

    uint32_t expected_data_out_size = sizeof(expected_data_out);

    uint8_t expected_tag[] = {0xd9, 0x68, 0xfa, 0x77, 0x05, 0x0c, 0xdb, 0x8e,
                              0xfc, 0xb9, 0x29, 0xbb, 0x21, 0x29, 0x30, 0xe1};

    uint32_t expected_tag_size = sizeof(expected_tag);

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(data_out_size == expected_data_out_size);
    DSEC_TEST_ASSERT(memcmp(expected_data_out, data_out, data_out_size) == 0);
    DSEC_TEST_ASSERT(tag_size == expected_tag_size);
    DSEC_TEST_ASSERT(memcmp(expected_tag, tag, tag_size) == 0);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_aes_256_big_buffer(void)
{
    int32_t result = 0;

    uint8_t key_data[] = {
        0x0b, 0x81, 0xcd, 0x35, 0x56, 0x1c, 0xce, 0xe0, 0x71, 0x11, 0x1b, 0x72,
        0xd0, 0x76, 0x2b, 0x17, 0x4b, 0x8b, 0x29, 0x8b, 0x6f, 0x9d, 0xa8, 0x30,
        0x69, 0x45, 0xd2, 0xc9, 0xd3, 0xc8, 0x89, 0x49};

    uint32_t key_data_size = sizeof(key_data);

    uint8_t* data_in = calloc(MAX_UDP_BUFFER_BYTES, sizeof(uint8_t));
    DSEC_TEST_ASSERT(data_in != NULL);
    uint32_t data_in_size = MAX_UDP_BUFFER_BYTES;

    uint8_t* data_out = calloc(MAX_UDP_BUFFER_BYTES, sizeof(uint8_t));
    DSEC_TEST_ASSERT(data_out != NULL);
    uint32_t data_out_size = MAX_UDP_BUFFER_BYTES;

    uint8_t iv[] = {0xfe, 0xd2, 0x28, 0x3a, 0xfc, 0x26, 0xa1, 0x85, 0x29, 0x80,
                    0xae, 0x92};

    uint32_t iv_size = sizeof(iv);

    uint8_t tag[16] = {1};
    uint32_t tag_size = sizeof(tag);

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_aes_128(void)
{
    int32_t result = 0;

    uint8_t data_out[100] = {1};
    uint32_t data_out_size = sizeof(data_out);

    uint8_t key_data[] = {
        0xbd, 0xbb, 0xe9, 0xfd, 0xcd, 0xaf, 0x14, 0x06, 0x3e, 0x9b, 0x09, 0xde,
        0xd6, 0x25, 0x80, 0x50};

    uint32_t key_data_size = sizeof(key_data);

    uint8_t data_in[] = {
        0x15, 0x03, 0x34, 0x00, 0x00, 0x00, 0x10, 0x00, 0xff, 0x00, 0x03, 0xc7,
        0xff, 0x00, 0x03, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x70, 0x00, 0x10, 0x00, 0xeb, 0xba, 0x3f, 0x10, 0xa7, 0x26, 0x5e, 0x06,
        0xc1, 0x05, 0x96, 0x5d, 0x00, 0x00, 0x01, 0x03, 0x71, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00};

    uint32_t data_in_size = sizeof(data_in);
    uint8_t iv[] = {
        0x0e, 0xcf, 0xf7, 0x03, 0x2b, 0x67, 0x0b, 0xa0, 0x1e, 0x46, 0x77, 0x31};

    uint32_t iv_size = sizeof(iv);

    uint8_t tag[16] = {1};
    uint32_t tag_size = sizeof(tag);

    uint8_t expected_data_out[] = {
        0x7d, 0x6e, 0x13, 0xc7, 0xd6, 0xac, 0x85, 0x26, 0x76, 0xc2, 0x4c, 0xdf,
        0x6d, 0x13, 0x49, 0xc9, 0x04, 0x69, 0x26, 0x55, 0xe2, 0x1b, 0x91, 0xae,
        0xee, 0x01, 0x50, 0xed, 0x05, 0x43, 0xfa, 0xb8, 0xe9, 0xf6, 0xa4, 0x67,
        0x26, 0x8b, 0xb2, 0x49, 0x18, 0x19, 0x7c, 0xc5, 0x4f, 0x8f, 0x21, 0x39,
        0xaf, 0x91, 0xdb, 0x8d, 0x29, 0x8b, 0x28, 0x65};

    uint32_t expected_data_out_size = sizeof(expected_data_out);

    uint8_t expected_tag[] = {
        0x80, 0xf6, 0xe8, 0xe6, 0x47, 0x03, 0xea, 0x9b, 0x2d, 0x03, 0x8b, 0x67,
        0x7d, 0x6b, 0x83, 0xcf};

    uint32_t expected_tag_size = sizeof(expected_tag);

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(data_out_size == expected_data_out_size);
    DSEC_TEST_ASSERT(memcmp(expected_data_out, data_out, data_out_size) == 0);
    DSEC_TEST_ASSERT(tag_size == expected_tag_size);
    DSEC_TEST_ASSERT(memcmp(expected_tag, tag, tag_size) == 0);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_aes_128_big_buffer(void)
{
    int32_t result = 0;

    uint8_t key_data[] = {
        0xbd, 0xbb, 0xe9, 0xfd, 0xcd, 0xaf, 0x14, 0x06, 0x3e, 0x9b, 0x09, 0xde,
        0xd6, 0x25, 0x80, 0x50};

    uint32_t key_data_size = sizeof(key_data);

    uint8_t data_in[MAX_UDP_BUFFER_BYTES] = {1};
    uint32_t data_in_size = MAX_UDP_BUFFER_BYTES;

    uint8_t data_out[MAX_UDP_BUFFER_BYTES] = {1};
    uint32_t data_out_size = MAX_UDP_BUFFER_BYTES;

    uint8_t iv[] = {
        0x0e, 0xcf, 0xf7, 0x03, 0x2b, 0x67, 0x0b, 0xa0, 0x1e, 0x46, 0x77, 0x31};

    uint32_t iv_size = sizeof(iv);

    uint8_t tag[16] = {1};
    uint32_t tag_size = sizeof(tag);

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_aes_encrypt_bad_parameters(void)
{
    int32_t result = 0;

    uint8_t data_out[220] = {1};
    uint32_t data_out_size = sizeof(data_out);

    uint8_t key_data[] = {
        0x0b, 0x81, 0xcd, 0x35, 0x56, 0x1c, 0xce, 0xe0, 0x71, 0x11, 0x1b, 0x72,
        0xd0, 0x76, 0x2b, 0x17, 0x4b, 0x8b, 0x29, 0x8b, 0x6f, 0x9d, 0xa8, 0x30,
        0x69, 0x45, 0xd2, 0xc9, 0xd3, 0xc8, 0x89, 0x49};

    uint32_t key_data_size = sizeof(key_data);

    uint8_t data_in[] = {
        0x0c, 0x01, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x01, 0x0f,
        0xeb, 0xba, 0x3f, 0x10, 0xa7, 0x26, 0x5e, 0x06, 0xc1, 0x05, 0x96, 0x5d,
        0x0e, 0x01, 0x0c, 0x00, 0xa6, 0xb1, 0xa0, 0x7e, 0x9c, 0x49, 0x9f, 0x45,
        0x3b, 0x68, 0x33, 0xad, 0x31, 0x01, 0x14, 0x00, 0x00, 0x00, 0x00, 0x02,
        0xa7, 0x51, 0x4f, 0xb7, 0x0e, 0xcf, 0xf7, 0x03, 0x21, 0x07, 0xa2, 0xbd,
        0xae, 0x54, 0xfe, 0xef, 0x30, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x0c,
        0xb6, 0xb5, 0x5f, 0x18, 0x26, 0xb0, 0x1d, 0x1c, 0x10, 0x60, 0x37, 0xc0,
        0x32, 0x01, 0x14, 0x00, 0xa2, 0x5a, 0xfd, 0x1e, 0xa7, 0x35, 0xd3, 0x57,
        0x9e, 0x93, 0xb2, 0xe6, 0x5a, 0x65, 0x1d, 0xb0, 0x00, 0x00, 0x00, 0x00,
        0x31, 0x01, 0x14, 0x00, 0x00, 0x00, 0x00, 0x02, 0xa7, 0x51, 0x4f, 0xb7,
        0x0e, 0xcf, 0xf7, 0x03, 0x2b, 0x67, 0x0b, 0xa0, 0x1e, 0x46, 0x77, 0x31,
        0x30, 0x01, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x38, 0x7d, 0x6e, 0x13, 0xc7,
        0xd6, 0xac, 0x85, 0x26, 0x76, 0xc2, 0x4c, 0xdf, 0x6d, 0x13, 0x49, 0xc9,
        0x04, 0x69, 0x26, 0x55, 0xe2, 0x1b, 0x91, 0xae, 0xee, 0x01, 0x50, 0xed,
        0x05, 0x43, 0xfa, 0xb8, 0xe9, 0xf6, 0xa4, 0x67, 0x26, 0x8b, 0xb2, 0x49,
        0x18, 0x19, 0x7c, 0xc5, 0x4f, 0x8f, 0x21, 0x39, 0xaf, 0x91, 0xdb, 0x8d,
        0x29, 0x8b, 0x28, 0x65, 0x32, 0x01, 0x14, 0x00, 0x80, 0xf6, 0xe8, 0xe6,
        0x47, 0x03, 0xea, 0x9b, 0x2d, 0x03, 0x8b, 0x67, 0x7d, 0x6b, 0x83, 0xcf,
        0x00, 0x00, 0x00, 0x00};

    uint32_t data_in_size = sizeof(data_in);
    uint8_t iv[] = {0xfe, 0xd2, 0x28, 0x3a, 0xfc, 0x26, 0xa1, 0x85, 0x29, 0x80,
                    0xae, 0x92};

    uint32_t iv_size = sizeof(iv);

    uint8_t tag[16] = {1};
    uint32_t tag_size = sizeof(tag);

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    /* NULL data_out */
    result = dsec_aes_encrypt(NULL,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL tag */
    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              NULL,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL key_data */
    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              NULL,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL data_in */
    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              NULL,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* NULL initalization vector */
    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              NULL,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    uint32_t bad_size = 0;

    /* Zero-sized data_out */
    result = dsec_aes_encrypt(data_out,
                              &bad_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Zero-sized tag */
    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &bad_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Zero-sized key_data */
    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              bad_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Zero-sized data_in */
    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              bad_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Zero-sized initalization vector */
    result = dsec_aes_encrypt(data_out,
                              &data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              bad_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* data_out smaller than data_in */
    uint32_t bad_data_out_size = data_in_size - 1;
    result = dsec_aes_encrypt(data_out,
                              &bad_data_out_size,
                              tag,
                              &tag_size,
                              &instance,
                              key_data,
                              key_data_size,
                              data_in,
                              data_in_size,
                              iv,
                              iv_size);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* key isn't 16-bit or 32-bit */
    for (size_t i = 0; i < 32; i++) {

        if (i == 16) {
            continue;
        }

        result = dsec_aes_encrypt(data_out,
                                  &data_out_size,
                                  tag,
                                  &tag_size,
                                  &instance,
                                  key_data,
                                  i,
                                  data_in,
                                  data_in_size,
                                  iv,
                                  iv_size);

        DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_aes_256),
    DSEC_TEST_CASE(test_case_aes_256_big_buffer),
    DSEC_TEST_CASE(test_case_aes_128),
    DSEC_TEST_CASE(test_case_aes_128_big_buffer),
    DSEC_TEST_CASE(test_case_aes_encrypt_bad_parameters),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "AES operation tests",
    .test_case_count = sizeof(test_case_table)/sizeof(test_case_table[0]),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
