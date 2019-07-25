/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_digest_ca.h>
#include <dsec_print.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_util.h>
#include <stdlib.h>
#include <string.h>

#define INPUT_SIZE 64
#define SHA256_SIZE 32

static const uint8_t golden_digest[SHA256_SIZE] = {
    0x66, 0x68, 0x7A, 0xAD, 0xF8, 0x62, 0xBD, 0x77, 0x6C, 0x8F, 0xC1, 0x8B,
    0x8E, 0x9F, 0x8E, 0x20, 0x08, 0x97, 0x14, 0x85, 0x6E, 0xE2, 0x33, 0xB3,
    0x90, 0x2A, 0x59, 0x1D, 0x0D, 0x5F, 0x29, 0x25 };

static void test_case_digest(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t result = DSEC_SUCCESS;
    const uint8_t input[INPUT_SIZE] = {0};
    uint8_t digest[SHA256_SIZE] = {0};
    uint32_t digest_size = SHA256_SIZE;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_sha256(digest, &digest_size, input, INPUT_SIZE, &instance);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(digest_size == SHA256_SIZE);
    result = memcmp(digest, golden_digest, digest_size);
    DSEC_TEST_ASSERT(result == 0);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_digest),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Digest test suite",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
