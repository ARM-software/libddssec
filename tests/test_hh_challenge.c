/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_hh.h>
#include <dsec_hh_challenge.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_util.h>

static void test_case_challenge_generate_get(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t hh_h = -1;
    int32_t result = 0;

    uint8_t challenge_local[1024];
    uint32_t output_size = DSEC_ARRAY_SIZE(challenge_local);

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_hh_challenge_get(challenge_local,
                                    &output_size,
                                    &instance,
                                    hh_h,
                                    1);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);
    DSEC_TEST_ASSERT(output_size == 0);

    DSEC_TEST_ASSERT(dsec_hh_create(&hh_h, &instance) == DSEC_SUCCESS);

    result = dsec_hh_challenge_get(challenge_local,
                                   &output_size,
                                   &instance,
                                   hh_h,
                                   1);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);
    DSEC_TEST_ASSERT(output_size == 0);

    result = dsec_hh_challenge_generate(&instance, hh_h, 600000, 1);
    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);
    result = dsec_hh_challenge_generate(&instance, hh_h, 512, 1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    result = dsec_hh_challenge_generate(&instance, hh_h, 512, 1);
    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    output_size = DSEC_ARRAY_SIZE(challenge_local);
    result = dsec_hh_challenge_get(challenge_local,
                                   &output_size,
                                   &instance,
                                   hh_h,
                                   1);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    output_size = 16;
    result = dsec_hh_challenge_get(challenge_local,
                                   &output_size,
                                   &instance,
                                   hh_h,
                                   1);

    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);

    DSEC_TEST_ASSERT(dsec_hh_challenge_unload(&instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_hh_delete(&instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_challenge_generate_get),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Challenge test suite",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
