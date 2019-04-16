/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ih.h>
#include <dsec_ih_ca.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_util.h>
#include <dsec_errno.h>

static void test_case_load_ca_from_builtin(void)
{
    static const char ca[] = "cacert.pem";

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(handle == 0);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    result = dsec_ih_ca_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(handle == 0);

    result = dsec_ih_ca_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_load_ca_invalid_then_valid(void)
{
    static const char ca[] = "cacert.pem";
    static const char ca_invalid[] = "invalid#.pem";

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    result = dsec_ih_ca_load(&instance, handle, ca_invalid);
    DSEC_TEST_ASSERT(result == DSEC_E_NOT_FOUND);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_ca_unload(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_load_invalid_ca(void)
{
    const char* test_invalid_ca[] = {
        /* Certificate missing a byte */
        "invalid_cacert_missing_byte.pem",
        /* 0 byte file */
        "invalid_cacert_empty.pem",
        /* Private Key */
        "invalid_cacert_mismatch1.pem",
        /* User certificate */
        "invalid_cacert_mismatch2.pem",
    };

    int32_t handle = -1;
    int32_t result = 0;
    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    for (size_t i = 0U; i < DSEC_ARRAY_SIZE(test_invalid_ca); i++) {
        result = dsec_ih_ca_load(&instance,
                                 handle,
                                 test_invalid_ca[i]);

        DSEC_TEST_ASSERT(result == DSEC_E_BAD_FORMAT);
    }

    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}


static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_load_ca_from_builtin),
    DSEC_TEST_CASE(test_case_load_ca_invalid_then_valid),
    DSEC_TEST_CASE(test_case_load_invalid_ca),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Certificate Authority API Tests",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
