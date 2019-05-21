/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ssh.h>
#include <dsec_hh.h>
#include <dsec_hh_dh.h>
#include <dsec_errno.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_util.h>

static void test_case_ssh_derive(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t hh_h = -1;
    int32_t result = 0;

    uint8_t dh_public[256];
    uint32_t dh_public_size = DSEC_ARRAY_SIZE(dh_public);

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    /* Invalid Handshake Handle. */
    DSEC_TEST_ASSERT(dsec_ssh_derive(&instance, hh_h) == DSEC_E_PARAM);

    DSEC_TEST_ASSERT(dsec_hh_create(&hh_h, &instance)  == DSEC_SUCCESS);

    /* Not all fields are available to deduce shared secret. */
    DSEC_TEST_ASSERT(dsec_ssh_derive(&instance, hh_h) == DSEC_E_DATA);

    DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h) == DSEC_SUCCESS);

    /* Missing the DH public key. */
    DSEC_TEST_ASSERT(dsec_ssh_derive(&instance, hh_h) == DSEC_E_DATA);

    result = dsec_hh_dh_set_public(&instance, hh_h, dh_public, dh_public_size);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ssh_derive(&instance, hh_h) == DSEC_SUCCESS);

    /* Cannot derive a second time. */
    DSEC_TEST_ASSERT(dsec_ssh_derive(&instance, hh_h) == DSEC_E_DATA);

    DSEC_TEST_ASSERT(dsec_hh_delete(&instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_ssh_derive),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Shared Secret Handle test suite",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
