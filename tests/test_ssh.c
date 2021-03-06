/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_hh_challenge.h>
#include <dsec_ssh.h>
#include <dsec_hh.h>
#include <dsec_hh_dh.h>
#include <dsec_errno.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <string.h>

static void test_case_ssh_derive(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t hh_h = -1;
    int32_t result = 0;
    int32_t ss_h = -1;
    int32_t old_ss_h = -1;

    uint8_t dh_public[256];
    uint32_t dh_public_size = sizeof(dh_public)/sizeof(dh_public[0]);

    uint8_t shared_key[256];
    uint32_t shared_key_size = sizeof(shared_key)/sizeof(shared_key[0]);
    uint8_t challenge1[256];
    uint32_t challenge1_size = sizeof(challenge1)/sizeof(challenge1[0]);
    uint8_t challenge2[256];
    uint32_t challenge2_size = sizeof(challenge2)/sizeof(challenge2[0]);
    uint8_t challenge2_out[256];
    uint32_t challenge2_out_size = sizeof(challenge2_out)/
                                   sizeof(challenge2_out[0]);

    for (uint32_t i = 0; i < challenge2_size; i++) {
        challenge2[i] = i;
    }

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    /* Invalid Handshake Handle. */
    DSEC_TEST_ASSERT(dsec_ssh_derive(&ss_h, &instance, hh_h) == DSEC_E_PARAM);
    DSEC_TEST_ASSERT(dsec_ssh_derive(NULL, &instance, hh_h) == DSEC_E_PARAM);

    DSEC_TEST_ASSERT(dsec_hh_create(&hh_h, &instance)  == DSEC_SUCCESS);

    /* Not all fields are available to deduce shared secret. */
    DSEC_TEST_ASSERT(dsec_ssh_derive(&ss_h, &instance, hh_h) == DSEC_E_DATA);

    DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h) == DSEC_SUCCESS);

    /* Missing the DH public key. */
    DSEC_TEST_ASSERT(dsec_ssh_derive(&ss_h, &instance, hh_h) == DSEC_E_DATA);

    result = dsec_hh_dh_set_public(&instance, hh_h, dh_public, dh_public_size);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_hh_challenge_generate(&instance, hh_h, challenge1_size, 1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_hh_challenge_get(challenge1,
                                   &challenge1_size,
                                   &instance,
                                   hh_h,
                                   1);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_hh_challenge_set(&instance,
                                   hh_h,
                                   challenge2,
                                   challenge2_size,
                                   2);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ssh_derive(&ss_h, &instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(ss_h == 0);

    result = dsec_ssh_get_data(shared_key,
                               &shared_key_size,
                               challenge1,
                               &challenge1_size,
                               challenge2_out,
                               &challenge2_out_size,
                               &instance,
                               ss_h);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(challenge1_size != 0);
    DSEC_TEST_ASSERT(challenge2_size != 0);
    DSEC_TEST_ASSERT(shared_key_size != 0);

    result = memcmp(challenge2_out, challenge2, challenge2_out_size);
    DSEC_TEST_ASSERT(result == 0);

    /* Cannot derive a second time. */
    old_ss_h = ss_h;
    DSEC_TEST_ASSERT(dsec_ssh_derive(&ss_h, &instance, hh_h) == DSEC_E_DATA);

    DSEC_TEST_ASSERT(dsec_hh_delete(&instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ssh_delete(&instance, old_ss_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ssh_delete(&instance, ss_h) == DSEC_E_DATA);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_ssh_failure_get_data(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t hh_h = -1;
    int32_t result = 0;
    int32_t ss_h = -1;

    uint8_t dh_public[256];
    uint32_t dh_public_size = sizeof(dh_public)/sizeof(dh_public[0]);

    uint8_t shared_key[256];
    uint32_t shared_key_size = sizeof(shared_key)/sizeof(shared_key[0]);
    uint8_t challenge1[256];
    uint32_t challenge1_size = sizeof(challenge1)/sizeof(challenge1[0]);
    uint8_t challenge2[256];
    uint32_t challenge2_size = sizeof(challenge2)/sizeof(challenge2[0]);

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_hh_create(&hh_h, &instance)  == DSEC_SUCCESS);

    result = dsec_ssh_get_data(shared_key,
                               &shared_key_size,
                               challenge1,
                               &challenge1_size,
                               challenge2,
                               &challenge2_size,
                               &instance,
                               0 /* Invalid ID for Shared Secret Handle */);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    result = dsec_ssh_get_data(shared_key,
                               &shared_key_size,
                               challenge1,
                               &challenge1_size,
                               challenge2,
                               &challenge2_size,
                               &instance,
                               -1 /* Invalid ID for Shared Secret Handle */);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h) == DSEC_SUCCESS);

    result = dsec_hh_dh_set_public(&instance, hh_h, dh_public, dh_public_size);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Reset challenge size */
    challenge1_size = sizeof(challenge1)/sizeof(challenge1[0]);
    challenge2_size = sizeof(challenge2)/sizeof(challenge2[0]);

    result = dsec_hh_challenge_generate(&instance, hh_h, challenge1_size, 1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_hh_challenge_set(&instance,
                                   hh_h,
                                   challenge2,
                                   challenge2_size,
                                   2);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ssh_derive(&ss_h, &instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(ss_h == 0);

    /* Short Buffer Shared Secret */
    shared_key_size = 4;
    challenge1_size = sizeof(challenge1)/sizeof(challenge1[0]);
    challenge2_size = sizeof(challenge2)/sizeof(challenge2[0]);
    result = dsec_ssh_get_data(shared_key,
                               &shared_key_size,
                               challenge1,
                               &challenge1_size,
                               challenge2,
                               &challenge2_size,
                               &instance,
                               ss_h);

    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);
    DSEC_TEST_ASSERT(challenge1_size == 0);
    DSEC_TEST_ASSERT(challenge2_size == 0);
    DSEC_TEST_ASSERT(shared_key_size == 0);

    /* Short Buffer Challenge 1 */
    shared_key_size = sizeof(shared_key)/sizeof(shared_key[0]);
    challenge1_size = 4;
    challenge2_size = sizeof(challenge2)/sizeof(challenge2[0]);
    result = dsec_ssh_get_data(shared_key,
                               &shared_key_size,
                               challenge1,
                               &challenge1_size,
                               challenge2,
                               &challenge2_size,
                               &instance,
                               ss_h);

    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);
    DSEC_TEST_ASSERT(challenge1_size == 0);
    DSEC_TEST_ASSERT(challenge2_size == 0);
    DSEC_TEST_ASSERT(shared_key_size == 0);

    /* Short Buffer Challenge 2 */
    shared_key_size = sizeof(shared_key)/sizeof(shared_key[0]);
    challenge1_size = sizeof(challenge1)/sizeof(challenge1[0]);
    challenge2_size = 4;
    result = dsec_ssh_get_data(shared_key,
                               &shared_key_size,
                               challenge1,
                               &challenge1_size,
                               challenge2,
                               &challenge2_size,
                               &instance,
                               ss_h);

    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);
    DSEC_TEST_ASSERT(challenge1_size == 0);
    DSEC_TEST_ASSERT(challenge2_size == 0);
    DSEC_TEST_ASSERT(shared_key_size == 0);

    /* NULL buffers */
    result = dsec_ssh_get_data(shared_key,
                               NULL,
                               challenge1,
                               NULL,
                               challenge2,
                               NULL,
                               &instance,
                               ss_h);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    DSEC_TEST_ASSERT(dsec_hh_delete(&instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ssh_delete(&instance, ss_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_full_process(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t result = 0;

    int32_t hh_h_p1 = -1;
    int32_t hh_h_p2 = -1;

    int32_t ss_h_p1 = -1;
    int32_t ss_h_p2 = -1;

    uint8_t dh_p1[256];
    uint32_t dh_p1_size = sizeof(dh_p1)/sizeof(dh_p1[0]);
    uint8_t dh_p2[256];
    uint32_t dh_p2_size = sizeof(dh_p2)/sizeof(dh_p2[0]);

    uint8_t c_p1[256];
    uint32_t c_p1_size = sizeof(c_p1)/sizeof(c_p1[0]);
    uint8_t c_p2[256];
    uint32_t c_p2_size = sizeof(c_p2)/sizeof(c_p2[0]);

    /* Extracted data from Participant 1 */
    uint8_t sk_p1[256];
    uint32_t sk_p1_size = sizeof(sk_p1)/sizeof(sk_p1[0]);
    uint8_t c1_p1[256];
    uint32_t c1_p1_size = sizeof(c1_p1)/sizeof(c1_p1[0]);
    uint8_t c2_p1[256];
    uint32_t c2_p1_size = sizeof(c2_p1)/sizeof(c2_p1[0]);

    /* Extracted data from Participant 2 */
    uint8_t sk_p2[256];
    uint32_t sk_p2_size = sizeof(sk_p2)/sizeof(sk_p2[0]);
    uint8_t c1_p2[256];
    uint32_t c1_p2_size = sizeof(c1_p2)/sizeof(c1_p2[0]);
    uint8_t c2_p2[256];
    uint32_t c2_p2_size = sizeof(c2_p2)/sizeof(c2_p2[0]);

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_hh_create(&hh_h_p1, &instance)  == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_hh_create(&hh_h_p2, &instance)  == DSEC_SUCCESS);

    /* Generate the challenge for p1 */
    result = dsec_hh_challenge_generate(&instance, hh_h_p1, c_p1_size, 1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    /* Get the challenge for p1 */
    result = dsec_hh_challenge_get(c_p1, &c_p1_size, &instance, hh_h_p1, 1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    /* Set p1 challenge to p2 */
    result = dsec_hh_challenge_set(&instance, hh_h_p2, c_p1, c_p1_size, 2);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Generate the challenge for p2 */
    result = dsec_hh_challenge_generate(&instance, hh_h_p2, c_p2_size, 1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    /* Get the challenge for p2 */
    result = dsec_hh_challenge_get(c_p2, &c_p2_size, &instance, hh_h_p2, 1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    /* Set p2 challenge to p1 */
    result = dsec_hh_challenge_set(&instance, hh_h_p1, c_p2, c_p2_size, 2);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Generate DH key pair for p2 */
    DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h_p2) == DSEC_SUCCESS);
    /* Get public key of p2 */
    result = dsec_hh_dh_get_public(dh_p2, &dh_p2_size, &instance, hh_h_p2);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    /* Set p2 public key to p1 */
    result = dsec_hh_dh_set_public(&instance, hh_h_p1, dh_p2, dh_p2_size);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    /* Generate DH key pair for p1 */
    DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h_p1) == DSEC_SUCCESS);
    /* Get public key of p1 */
    result = dsec_hh_dh_get_public(dh_p1, &dh_p1_size, &instance, hh_h_p1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    /* Set p1 public key to p2 */
    result = dsec_hh_dh_set_public(&instance, hh_h_p2, dh_p1, dh_p1_size);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Derive the secrets */
    result = dsec_ssh_derive(&ss_h_p1, &instance, hh_h_p1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(ss_h_p1 == 0);
    result = dsec_ssh_derive(&ss_h_p2, &instance, hh_h_p2);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(ss_h_p2 == 1);

    /* Get the data and compare the extracted arrays */
    result = dsec_ssh_get_data(sk_p1, &sk_p1_size,
                               c1_p1, &c1_p1_size,
                               c2_p1, &c2_p1_size,
                               &instance, ss_h_p1);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ssh_get_data(sk_p2, &sk_p2_size,
                               c1_p2, &c1_p2_size,
                               c2_p2, &c2_p2_size,
                               &instance, ss_h_p2);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(sk_p2_size == sk_p1_size);
    DSEC_TEST_ASSERT(c1_p2_size == c2_p1_size);
    DSEC_TEST_ASSERT(c2_p2_size == c1_p1_size);

    DSEC_TEST_ASSERT(memcmp(sk_p1, sk_p2, sk_p1_size) == 0);
    DSEC_TEST_ASSERT(memcmp(c1_p2, c2_p1, c1_p2_size) == 0);
    DSEC_TEST_ASSERT(memcmp(c2_p2, c1_p1, c2_p2_size) == 0);

    DSEC_TEST_ASSERT(dsec_hh_delete(&instance, hh_h_p1) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_hh_delete(&instance, hh_h_p2) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ssh_delete(&instance, ss_h_p1) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ssh_delete(&instance, ss_h_p2) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_failure_unload(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t result = 0;

    int32_t hh_h = -1;
    int32_t ss_h = -1;

    uint8_t dh[256];
    uint32_t dh_size = sizeof(dh)/sizeof(dh[0]);

    uint8_t c[256];
    uint32_t c_size = sizeof(c)/sizeof(c[0]);

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    /* Handle not created */
    DSEC_TEST_ASSERT(dsec_ssh_delete(&instance, -1) == DSEC_E_DATA);
    DSEC_TEST_ASSERT(dsec_ssh_delete(&instance, 0) == DSEC_E_DATA);

    DSEC_TEST_ASSERT(dsec_hh_create(&hh_h, &instance) == DSEC_SUCCESS);
    /* Generate the challenge */
    result = dsec_hh_challenge_generate(&instance, hh_h, c_size, 1);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    /* Set challenge */
    result = dsec_hh_challenge_set(&instance, hh_h, c, c_size, 2);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    /* Set public key */
    result = dsec_hh_dh_set_public(&instance, hh_h, dh, dh_size);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    /* Generate DH key pair */
    DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h) == DSEC_SUCCESS);
    /* Derive the secrets */
    DSEC_TEST_ASSERT(dsec_ssh_derive(&ss_h, &instance, hh_h) == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_hh_delete(&instance, hh_h) == DSEC_SUCCESS);

    /* Double free */
    DSEC_TEST_ASSERT(dsec_ssh_delete(&instance, ss_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ssh_delete(&instance, ss_h) == DSEC_E_DATA);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_get_info(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t result = 0;

    struct ssh_info_t ssh_info = {.max_handle = 0, .allocated_handle = 0};

    int32_t hh_h = -1;
    int32_t ss_h = -1;

    uint8_t dh[256];
    uint32_t dh_size = sizeof(dh)/sizeof(dh[0]);

    uint8_t c[256];
    uint32_t c_size = sizeof(c)/sizeof(c[0]);

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ssh_get_info(NULL, &instance) == DSEC_E_PARAM);
    DSEC_TEST_ASSERT(dsec_ssh_get_info(NULL, NULL) == DSEC_E_PARAM);

    DSEC_TEST_ASSERT(dsec_ssh_get_info(&ssh_info, &instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(ssh_info.max_handle > 0);
    DSEC_TEST_ASSERT(ssh_info.max_handle < INT32_MAX);
    DSEC_TEST_ASSERT(ssh_info.allocated_handle == 0);

    for (uint32_t i = 0; i < ssh_info.max_handle; i++) {
        DSEC_TEST_ASSERT(dsec_hh_create(&hh_h, &instance) == DSEC_SUCCESS);
        /* Generate the challenge */
        result = dsec_hh_challenge_generate(&instance, hh_h, c_size, 1);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        /* Set challenge */
        result = dsec_hh_challenge_set(&instance, hh_h, c, c_size, 2);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        /* Set public key */
        result = dsec_hh_dh_set_public(&instance, hh_h, dh, dh_size);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        /* Generate DH key pair */
        DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h) == DSEC_SUCCESS);
        /* Derive the secrets */
        result = dsec_ssh_derive(&ss_h, &instance, hh_h);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(ss_h == (int32_t)i);
        result = dsec_ssh_get_info(&ssh_info, &instance);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(ssh_info.allocated_handle == (i+1));
        DSEC_TEST_ASSERT(dsec_hh_delete(&instance, hh_h) == DSEC_SUCCESS);
    }

    for (uint32_t i = 0; i < ssh_info.max_handle; i++) {
        DSEC_TEST_ASSERT(dsec_ssh_delete(&instance, i) == DSEC_SUCCESS);

        result = dsec_ssh_get_info(&ssh_info, &instance);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

        uint32_t allocated_handles = ssh_info.max_handle - (i+1);
        DSEC_TEST_ASSERT(ssh_info.allocated_handle == allocated_handles);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_ssh_derive),
    DSEC_TEST_CASE(test_case_ssh_failure_get_data),
    DSEC_TEST_CASE(test_case_full_process),
    DSEC_TEST_CASE(test_case_failure_unload),
    DSEC_TEST_CASE(test_case_get_info),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Shared Secret Handle test suite",
    .test_case_count = sizeof(test_case_table)/sizeof(test_case_table[0]),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
