/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_ih.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>

/*
 * Allocate and delete handles sequencially.
 * Make sure that the number of allocated handle stays at 0
 */
static void test_case_ih_load_unload(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t ih_h = -1;
    int32_t result = 0;

    uint32_t max_ih = 0;
    uint32_t current_ih_num = 0;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_ih_get_info(&max_ih, &current_ih_num, &instance);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(max_ih > 0);
    DSEC_TEST_ASSERT(current_ih_num == 0);

    for (uint32_t i = 0; i < max_ih; i++) {
        result = dsec_ih_create(&ih_h, &instance);
        DSEC_TEST_ASSERT(ih_h == (int32_t)0);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

        result = dsec_ih_delete(&instance, ih_h);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        result = dsec_ih_get_info(&max_ih, &current_ih_num, &instance);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(current_ih_num == 0);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

/*
 * Allocate the maximum number of handles and delete them all.
 * Make sure that no more handles can be allocated once the maximum number is
 * reached.
 */
static void test_case_ih_load_max(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t ih_h = -1;
    int32_t result = 0;

    uint32_t max_ih_origin = 0;
    uint32_t max_ih = 0;
    uint32_t current_ih_num = 0;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_ih_get_info(&max_ih_origin, &current_ih_num, &instance);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(max_ih_origin > 0);
    DSEC_TEST_ASSERT(current_ih_num == 0);

    for (uint32_t i = 0; i < max_ih_origin; i++) {
        result = dsec_ih_create(&ih_h, &instance);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(ih_h == (int32_t)i);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

        result = dsec_ih_get_info(&max_ih, &current_ih_num, &instance);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(max_ih == max_ih_origin);
        DSEC_TEST_ASSERT(current_ih_num == i + 1);
    }

    result = dsec_ih_create(&ih_h, &instance);
    DSEC_TEST_ASSERT(result == DSEC_E_MEMORY);

    result = dsec_ih_delete(&instance, (int32_t)150);
    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    result = dsec_ih_get_info(&max_ih, &current_ih_num, &instance);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(current_ih_num == max_ih);

    for (uint32_t i = 0; i < max_ih_origin; i++) {
        result = dsec_ih_delete(&instance, (int32_t)i);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    result = dsec_ih_get_info(&max_ih, &current_ih_num, &instance);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(current_ih_num == 0);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

/* Make sure that a deleted handle cannot be deleted a second time */
static void test_case_ih_unload_unloaded(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t ih_h = -1;
    int32_t result = 0;

    uint32_t max_ih = 0;
    uint32_t current_ih_num = 0;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    result = dsec_ih_get_info(&max_ih, &current_ih_num, &instance);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(max_ih > 0);
    DSEC_TEST_ASSERT(current_ih_num == 0);

    for (uint32_t i = 0; i < max_ih; i++) {
        result = dsec_ih_create(&ih_h, &instance);
        DSEC_TEST_ASSERT(ih_h == (int32_t)i);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    for (uint32_t i = 0; i < max_ih; i++) {
        result = dsec_ih_delete(&instance, i);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    for (uint32_t i = 0; i < max_ih; i++) {
        result = dsec_ih_delete(&instance, i);
        DSEC_TEST_ASSERT(result == DSEC_E_PARAM);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_ih_multiple_contexts(void)
{
    TEEC_Session session1;
    TEEC_Context context1;

    TEEC_Session session2;
    TEEC_Context context2;

    int32_t ih_h = -1;
    int32_t result = 0;

    struct dsec_instance inst1 = dsec_ca_instance_create(&session1, &context1);
    struct dsec_instance inst2 = dsec_ca_instance_create(&session2, &context2);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&inst1) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&inst2) == DSEC_SUCCESS);

    result = dsec_ih_create(&ih_h, &inst1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(ih_h == 0);

    result = dsec_ih_create(&ih_h, &inst2);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(ih_h == 0);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&inst1) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&inst2) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_ih_load_unload),
    DSEC_TEST_CASE(test_case_ih_load_max),
    DSEC_TEST_CASE(test_case_ih_unload_unloaded),
    DSEC_TEST_CASE(test_case_ih_multiple_contexts),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Identity Handle test suite",
    .test_case_count = sizeof(test_case_table)/sizeof(test_case_table[0]),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
