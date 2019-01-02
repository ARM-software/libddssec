/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <dsec_errno.h>
#include <dsec_rand.h>
#include <dsec_test.h>
#include <dsec_util.h>

static void test_case_rand_pointer(void)
{
    DSEC_TEST_ASSERT(dsec_rand(NULL, 1) == DSEC_E_PARAM);
}

static void test_case_rand_nbytes(void)
{
    uint8_t buffer[257];

    DSEC_TEST_ASSERT(dsec_rand(&buffer, 0) == DSEC_E_PARAM);
    DSEC_TEST_ASSERT(dsec_rand(&buffer, 257) == DSEC_E_PARAM);
}

static void test_case_rand_data(void)
{
    #define SIZE 24
    uint8_t buffer1[SIZE] = {0};
    uint8_t buffer2[SIZE] = {0};

    /* Ensure function completes with valid parameters */
    DSEC_TEST_ASSERT(dsec_rand(buffer1, SIZE) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_rand(buffer2, SIZE) == DSEC_SUCCESS);

    /*
     * Basic validation to ensure buffers got written. Note that buffers are
     * big enough (192 bits) to be unlikely they will ever collide.
     */
    DSEC_TEST_ASSERT(memcmp(buffer1, buffer2, SIZE) != 0);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_rand_pointer),
    DSEC_TEST_CASE(test_case_rand_nbytes),
    DSEC_TEST_CASE(test_case_rand_data),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Rand",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
};
