/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_hh.h>
#include <dsec_errno.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>

static void test_case_hh_load_unload(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t hh_h = -1;
    int32_t result = 0;

    uint32_t max_hh = 0;
    uint32_t current_hh_num = 0;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_hh_get_info(&max_hh, &current_hh_num, &instance);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(max_hh > 0);
    DSEC_TEST_ASSERT(current_hh_num == 0);

    for (uint32_t i = 0; i < max_hh; i++) {
        result = dsec_hh_create(&hh_h, &instance);
        DSEC_TEST_ASSERT(hh_h == (int32_t)0);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

        result = dsec_hh_delete(&instance, hh_h);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        result = dsec_hh_get_info(&max_hh, &current_hh_num, &instance);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(current_hh_num == 0);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);

}

static void test_case_hh_load_max(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t hh_h = -1;
    int32_t result = 0;

    uint32_t max_hh_origin = 0;
    uint32_t max_hh = 0;
    uint32_t current_hh_num = 0;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_hh_get_info(&max_hh_origin, &current_hh_num, &instance);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(max_hh_origin > 0);
    DSEC_TEST_ASSERT(current_hh_num == 0);

    for (uint32_t i = 0; i < max_hh_origin; i++) {
        result = dsec_hh_create(&hh_h, &instance);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(hh_h == (int32_t)i);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

        result = dsec_hh_get_info(&max_hh, &current_hh_num, &instance);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(max_hh == max_hh_origin);
        DSEC_TEST_ASSERT(current_hh_num == i + 1);
    }
    result = dsec_hh_delete(&instance, (int32_t)150);
    result = dsec_hh_get_info(&max_hh, &current_hh_num, &instance);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(current_hh_num == max_hh);

    for (uint32_t i = 0; i < max_hh_origin; i++) {
        result = dsec_hh_delete(&instance, (int32_t)i);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    result = dsec_hh_get_info(&max_hh, &current_hh_num, &instance);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(current_hh_num == 0);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_hh_multiple_load_unload(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t hh_h = -1;
    int32_t result = 0;

    uint32_t max_hh = 0;
    uint32_t current_hh_num = 0;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_hh_get_info(&max_hh, &current_hh_num, &instance);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(max_hh > 0);
    DSEC_TEST_ASSERT(current_hh_num == 0);

    for (uint32_t i = 0; i < max_hh; i++) {
        result = dsec_hh_create(&hh_h, &instance);
        DSEC_TEST_ASSERT(hh_h == (int32_t)i);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    for (uint32_t i = 0; i < max_hh; i++) {
        result = dsec_hh_delete(&instance, i);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    for (uint32_t i = 0; i < max_hh; i++) {
        result = dsec_hh_delete(&instance, i);
        DSEC_TEST_ASSERT(result == DSEC_E_PARAM);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_hh_load_unload),
    DSEC_TEST_CASE(test_case_hh_load_max),
    DSEC_TEST_CASE(test_case_hh_multiple_load_unload),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Handshake Handle test suite",
    .test_case_count = sizeof(test_case_table)/sizeof(test_case_table[0]),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
