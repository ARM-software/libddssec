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
#include <string.h>

static void test_case_load_ca_from_builtin(void)
{
    static const char ca[] = "assets/cacert.pem";

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
    static const char ca[] = "assets/cacert.pem";
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
        "assets/invalid_cacert_missing_byte.pem",
        /* 0 byte file */
        "assets/invalid_cacert_empty.pem",
        /* Private Key */
        "assets/invalid_cacert_mismatch1.pem",
        /* User certificate */
        "assets/invalid_cacert_mismatch2.pem",
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

static void test_case_get_attributes_ca(void)
{
    static const char ca[] = "assets/cacert.pem";

    int32_t handle = -1;
    uint8_t output_sn[2048] = {0};
    uint32_t output_sn_size = DSEC_ARRAY_SIZE(output_sn);
    static const char expected_sn[] = "C=UK, ST=CB, L=Cambridge, O=Arm, "
                                      "CN=libddssecCerticateAuthority, "
                                      "emailAddress=mainca@arm.com";

    uint32_t expected_sn_size = DSEC_ARRAY_SIZE(expected_sn);

    uint8_t output_sign_algo[128] = {0};
    uint32_t output_sign_algo_size = DSEC_ARRAY_SIZE(output_sign_algo);
    static const char expected_sign_algo[] = "ECDSA with SHA256";
    uint32_t expected_sign_algo_size = DSEC_ARRAY_SIZE(expected_sign_algo);

    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_ca_get_sn(output_sn, &output_sn_size, &instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(output_sn_size == expected_sn_size);
    DSEC_TEST_ASSERT(
        memcmp((char*)output_sn, expected_sn, expected_sn_size) == 0);

    result = dsec_ih_ca_get_signature_algorithm(output_sign_algo,
                                                &output_sign_algo_size,
                                                &instance,
                                                handle);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(output_sign_algo_size == expected_sign_algo_size);
    DSEC_TEST_ASSERT(memcmp((char*)output_sign_algo,
                            expected_sign_algo,
                            expected_sign_algo_size) == 0);

    result = dsec_ih_ca_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_get_attributes_ca_invalid(void)
{
    static const char ca[] = "assets/cacert.pem";

    uint8_t output_sn[2048] = {0};
    uint32_t output_sn_size = DSEC_ARRAY_SIZE(output_sn);
    uint8_t output_sign_algo[128] = {0};
    uint32_t output_sign_algo_size = DSEC_ARRAY_SIZE(output_sign_algo);

    uint8_t output_short[8] = {0};
    uint32_t output_short_size = DSEC_ARRAY_SIZE(output_short);

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    /* The CA has not been loaded to the Identity Handle yet. */
    result = dsec_ih_ca_get_sn(output_sn, &output_sn_size, &instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_E_DATA);
    DSEC_TEST_ASSERT(output_sn_size == 0);
    output_sn_size = DSEC_ARRAY_SIZE(output_sn);
    result = dsec_ih_ca_get_signature_algorithm(output_sign_algo,
                                                &output_sign_algo_size,
                                                &instance,
                                                handle);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);
    DSEC_TEST_ASSERT(output_sign_algo_size == 0);
    output_sign_algo_size = DSEC_ARRAY_SIZE(output_sign_algo);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Buffer is too small. */
    result = dsec_ih_ca_get_sn(output_short,
                               &output_short_size,
                               &instance,
                               handle);

    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);

    output_short_size = DSEC_ARRAY_SIZE(output_short);
    result = dsec_ih_ca_get_signature_algorithm(output_short,
                                                &output_short_size,
                                                &instance,
                                                handle);

    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);


    result = dsec_ih_ca_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* The CA has been unloaded. */
    result = dsec_ih_ca_get_sn(output_sn, &output_sn_size, &instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_E_DATA);
    DSEC_TEST_ASSERT(output_sn_size == 0);
    result = dsec_ih_ca_get_signature_algorithm(output_sign_algo,
                                                &output_sign_algo_size,
                                                &instance,
                                                handle);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);
    DSEC_TEST_ASSERT(output_sign_algo_size == 0);

    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_load_ca_from_builtin),
    DSEC_TEST_CASE(test_case_load_ca_invalid_then_valid),
    DSEC_TEST_CASE(test_case_load_invalid_ca),
    DSEC_TEST_CASE(test_case_get_attributes_ca),
    DSEC_TEST_CASE(test_case_get_attributes_ca_invalid),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Certificate Authority API Tests",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
