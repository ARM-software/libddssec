/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <test_manage_object_ca.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_test_canary.h>
#include <string.h>

static void test_case_load_builtin(void)
{
    static const char name[] = "assets/cacert.pem";
    size_t name_size = sizeof(name)/sizeof(name[0]);
    TEEC_Result result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc(name_size*sizeof(char));
    strncpy(canaried_name, name, name_size);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 name_size,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
}

static void test_case_load_builtin_overload(void)
{
    static const char name[] = "assets/cacert.pem";
    size_t name_size = sizeof(name)/sizeof(name[0]);
    TEEC_Result result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc(name_size*sizeof(char));
    strncpy(canaried_name, name, name_size);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 strlen(canaried_name)+1,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 strlen(canaried_name)+1,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_ERROR_ITEM_NOT_FOUND);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
}

/*
 * Attempts to load cacert.pem (with a mis-spelling) so it tries to load an
 * objet that does not exist
 */
static void test_case_load_builtin_miss(void)
{
    static const char name[] = "carrot";
    size_t name_size = sizeof(name)/sizeof(name[0]);
    TEEC_Result result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc(name_size*sizeof(char));
    strncpy(canaried_name, name, name_size);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 name_size,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_ERROR_ITEM_NOT_FOUND);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
}

static void test_case_unload_builtin(void)
{
    static const char name[] = "assets/cacert.pem";
    size_t name_size = sizeof(name)/sizeof(name[0]);
    TEEC_Result result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc(name_size*sizeof(char));
    strncpy(canaried_name, name, name_size);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 strlen(canaried_name)+1,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = unload_object(&instance);
    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 strlen(canaried_name)+1,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_load_builtin),
    DSEC_TEST_CASE(test_case_load_builtin_overload),
    DSEC_TEST_CASE(test_case_load_builtin_miss),
    DSEC_TEST_CASE(test_case_unload_builtin),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Manage secure objects",
    .test_case_count = sizeof(test_case_table)/sizeof(test_case_table[0]),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
