/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ca.h>
#include <dsec_errno.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_util.h>

static void test_case_open(void)
{
    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(instance.open == true);
    DSEC_TEST_ASSERT(instance.context != NULL);
    DSEC_TEST_ASSERT(instance.session != NULL);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(instance.open == false);
}

static void test_case_open_already_open(void)
{
    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_E_INIT);
    dsec_ca_instance_close(&instance);
}

static void test_case_open_null(void)
{
    DSEC_TEST_ASSERT(dsec_ca_instance_open(NULL) == DSEC_E_PARAM);
}

static void test_case_open_null_session(void)
{
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(NULL, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_E_PARAM);
}

static void test_case_open_null_context(void)
{
    TEEC_Session session;

    struct dsec_instance instance = dsec_ca_instance_create(&session, NULL);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_E_PARAM);
}

static void test_case_open_forced_open(void)
{
    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    instance.open = true;

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_E_INIT);
}

static void test_case_close(void)
{
    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_close_null(void)
{
    DSEC_TEST_ASSERT(dsec_ca_instance_close(NULL) == DSEC_E_PARAM);
}

static void test_case_close_already_closed(void)
{
    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_E_INIT);
}

static void test_case_close_unopened(void)
{
    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_E_INIT);
}

static void test_case_multiple_contexts(void)
{
    TEEC_Session session1;
    TEEC_Context context1;
    TEEC_Session session2;
    TEEC_Context context2;

    struct dsec_instance inst1 = dsec_ca_instance_create(&session1, &context1);
    struct dsec_instance inst2 = dsec_ca_instance_create(&session2, &context2);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&inst1) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&inst2) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&inst1) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&inst2) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_open),
    DSEC_TEST_CASE(test_case_open_null),
    DSEC_TEST_CASE(test_case_open_null_session),
    DSEC_TEST_CASE(test_case_open_null_context),
    DSEC_TEST_CASE(test_case_open_already_open),
    DSEC_TEST_CASE(test_case_open_forced_open),
    DSEC_TEST_CASE(test_case_close),
    DSEC_TEST_CASE(test_case_close_null),
    DSEC_TEST_CASE(test_case_close_already_closed),
    DSEC_TEST_CASE(test_case_close_unopened),
    DSEC_TEST_CASE(test_case_multiple_contexts),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Common client application helper functions",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
