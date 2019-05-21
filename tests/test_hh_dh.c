/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_hh.h>
#include <dsec_hh_dh.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_util.h>

static void test_case_dh_generate_get_public(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t hh_h = -1;
    int32_t result = 0;

    uint8_t dh_pair[1024];
    uint32_t buffer_size = DSEC_ARRAY_SIZE(dh_pair);
    uint32_t output_size = DSEC_ARRAY_SIZE(dh_pair);

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_hh_create(&hh_h, &instance) == DSEC_SUCCESS);

    /* DH is not generated */
    result = dsec_hh_dh_get_public(dh_pair, &output_size, &instance, hh_h);
    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h) == DSEC_SUCCESS);
    /* DH is already generated */
    DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h) == DSEC_E_DATA);

    /* Return the data */
    result = dsec_hh_dh_get_public(dh_pair, &buffer_size, &instance, hh_h);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Buffer is too short */
    buffer_size = 4;
    result = dsec_hh_dh_get_public(dh_pair, &buffer_size, &instance, hh_h);
    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);

    DSEC_TEST_ASSERT(dsec_hh_dh_unload(&instance, hh_h) == DSEC_SUCCESS);
    /* Success even if the data was already free for the handle. */
    DSEC_TEST_ASSERT(dsec_hh_dh_unload(&instance, hh_h) == DSEC_SUCCESS);

    /* A new key can be generated */
    DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h) == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_hh_dh_unload(&instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_hh_delete(&instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_dh_generate_get_public),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Diffie Hellman test suite",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
