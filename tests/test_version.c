/*
 * DDS Security library
 * Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_test.h>
#include <dsec_util.h>
#include <dsec_version.h>
#include <stddef.h>

static void test_case_version_pointer(void)
{
    const char *version;

    version = dsec_version();
    DSEC_TEST_ASSERT(version != NULL);
}

static const struct dsec_test_case_desc test_case_table[] = {
        DSEC_TEST_CASE(test_case_version_pointer),
};

const struct dsec_test_suite_desc test_suite = {
        .name = "Version",
        .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
        .test_case_table = test_case_table,
};
