/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_test.h>
#include <dsec_test_canary.h>
#include <dsec_util.h>
#include <stddef.h>
#include <stdint.h>

static void test_case_canary_alloc(void)
{
    void* buf;

    buf = dsec_test_canary_alloc(35);
    DSEC_TEST_ASSERT(buf != NULL);
    DSEC_TEST_ASSERT(dsec_test_canary_check(buf) == DSEC_SUCCESS);
    dsec_test_canary_free(buf);
}

static void test_case_canary_alloc_zero(void)
{
    void* buf;

    buf = dsec_test_canary_alloc(0);
    DSEC_TEST_ASSERT(buf != NULL);
    DSEC_TEST_ASSERT(dsec_test_canary_check(buf) == DSEC_SUCCESS);
    dsec_test_canary_free(buf);
}

static void test_case_canary_check_null(void)
{
    DSEC_TEST_ASSERT(dsec_test_canary_check(NULL) == DSEC_E_PARAM);
}

static void test_case_canary_corrupt_low(void)
{
    uint8_t* buf;

    buf = (uint8_t*)dsec_test_canary_alloc(1);
    DSEC_TEST_ASSERT(buf != NULL);

    /* Corrupt byte before the buffer */
    buf[-1] = 0xff;

    DSEC_TEST_ASSERT(dsec_test_canary_check(buf) == DSEC_E_DATA);
    dsec_test_canary_free(buf);
}

static void test_case_canary_corrupt_high(void)
{
    uint8_t* buf;

    buf = (uint8_t*)dsec_test_canary_alloc(1);
    DSEC_TEST_ASSERT(buf != NULL);

    /* Corrupt byte after the buffer */
    buf[1] = 0xff;

    DSEC_TEST_ASSERT(dsec_test_canary_check(buf) == DSEC_E_DATA);
    dsec_test_canary_free(buf);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_canary_alloc),
    DSEC_TEST_CASE(test_case_canary_alloc_zero),
    DSEC_TEST_CASE(test_case_canary_check_null),
    DSEC_TEST_CASE(test_case_canary_corrupt_low),
    DSEC_TEST_CASE(test_case_canary_corrupt_high),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Canary",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
};
