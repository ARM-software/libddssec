/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_session_key.h>
#include <dsec_key_material.h>
#include <dsec_errno.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <string.h>

static void test_case_session_key_create(void)
{
    int32_t result = 0;
    int32_t km_handle_id = 0;
    uint8_t session_key[32] = {0};

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance inst = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&inst) == DSEC_SUCCESS);

    result = dsec_session_key_create_and_get(session_key,
                                             &inst,
                                             km_handle_id,
                                             0,
                                             false);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    for (int32_t i = 0; i < 8; i++) {
        bool use_gmac = ((i % 2) == 0);
        bool use_256_bits = ((i % 4) < 2);
        bool receiver_specific = ((i % 2) == 0);
        uint32_t session_id = i * 10;

        result = dsec_key_material_create(&km_handle_id,
                                          &inst,
                                          use_gmac,
                                          use_256_bits);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

        result = dsec_session_key_create_and_get(session_key,
                                                 &inst,
                                                 km_handle_id,
                                                 session_id,
                                                 receiver_specific);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        result = dsec_key_material_delete(&inst, km_handle_id);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&inst) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_session_key_create),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Session key tests",
    .test_case_count = sizeof(test_case_table)/sizeof(test_case_table[0]),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
