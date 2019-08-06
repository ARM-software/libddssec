/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ca.h>
#include <dsec_errno.h>
#include <dsec_ta.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_test_canary.h>
#include <dsec_util.h>
#include <string.h>

static void test_case_internal_hmac(void)
{
    TEEC_Session session;
    TEEC_Context context;

    uint32_t origin = 0;
    TEEC_Operation operation = {0};
    TEEC_Result result = 0;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);


    for (uint32_t test_id = 0; test_id < 2; test_id++) {
        operation.params[0].value.a = test_id;
        result = dsec_ca_invoke(&instance,
                                DSEC_TA_CMD_HMAC_TESTS,
                                &operation,
                                &origin);

        DSEC_TEST_ASSERT(result == TEEC_SUCCESS);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}


static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_internal_hmac),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "HMAC internal function",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
