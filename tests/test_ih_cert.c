/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ih.h>
#include <dsec_ih_ca.h>
#include <dsec_ih_cert.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_util.h>
#include <dsec_errno.h>
#include <string.h>

static void test_case_load_cert_from_builtin(void)
{
    static const char ca[] = "cacert.pem";
    static const char cert[] = "p1cert.pem";

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_load(&instance, handle, cert);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_load(&instance, handle, cert);
    DSEC_TEST_ASSERT(result != DSEC_SUCCESS);

    result = dsec_ih_cert_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_ca_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_invalid_load_cert(void)
{
    static const char ca[] = "cacert.pem";

    struct invalid_cert {
        char* name;
        int32_t dsec_result_expected;
    };

    const struct invalid_cert cert_invalid[] = {
        /* This is a public key */
        {"invalid_nosignature_cert.pem", DSEC_E_BAD_FORMAT},
        /* Certificate is signed by another CA */
        {"invalid_signature_cert.pem", DSEC_E_SECURITY},
        /* Certificate signature expired */
        {"invalid_p1_cert_shortterm_signed.pem", DSEC_E_SECURITY},
        /* Does not exist */
        {"does_not_exist.pem", DSEC_E_NOT_FOUND},
        /* Mismatch type */
        {"p1privkey.pem", DSEC_E_BAD_FORMAT},
    };

    static const char cert_valid[] = "p1cert.pem";

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    for (size_t i = 0U; i < DSEC_ARRAY_SIZE(cert_invalid); i++) {
        result = dsec_ih_cert_load(&instance,
                                   handle,
                                   cert_invalid[i].name);

        DSEC_TEST_ASSERT(result == cert_invalid[i].dsec_result_expected);
    }

    result = dsec_ih_cert_unload(&instance, handle);
    DSEC_TEST_ASSERT(result != DSEC_SUCCESS);

    result = dsec_ih_ca_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_load(&instance, handle, cert_valid);
    DSEC_TEST_ASSERT(result != DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_get_loaded_cert(void)
{
    static const char ca[] = "cacert.pem";
    static const char cert_valid[] = "p1cert.pem";

    uint8_t output_certificate[2048] = {0};
    uint32_t output_certificate_size = DSEC_ARRAY_SIZE(output_certificate);

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_load(&instance, handle, cert_valid);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_get(output_certificate,
                              &output_certificate_size,
                              &instance,
                              handle);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(
        (output_certificate_size > 0U) &&
        (strstr((char*)output_certificate,
                "-----BEGIN CERTIFICATE-----\n") != NULL) &&
        (strstr((char*)output_certificate,
                "\n-----END CERTIFICATE-----\0") != NULL));

    result = dsec_ih_cert_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_ca_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_get_loaded_cert_invalid(void)
{
    static const char ca[] = "cacert.pem";
    static const char cert_valid[] = "p1cert.pem";

    uint8_t output_certificate[2048] = {0};
    uint32_t output_certificate_size = DSEC_ARRAY_SIZE(output_certificate);

    uint8_t output_short[8] = {0};
    uint32_t output_short_size = DSEC_ARRAY_SIZE(output_short);

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    result = dsec_ih_cert_get(output_certificate,
                              &output_certificate_size,
                              &instance,
                              handle);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_get(output_certificate,
                              &output_certificate_size,
                              &instance,
                              handle);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    result = dsec_ih_cert_load(&instance, handle, cert_valid);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_get(output_short,
                              &output_short_size,
                              &instance,
                              handle);

    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);
    DSEC_TEST_ASSERT(
        (strstr((char*)output_certificate,
                "-----BEGIN CERTIFICATE-----\n") == NULL) &&
        (strstr((char*)output_certificate,
                "\n-----END CERTIFICATE-----\0") == NULL));

    result = dsec_ih_cert_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_ca_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_load_cert_from_builtin),
    DSEC_TEST_CASE(test_case_invalid_load_cert),
    DSEC_TEST_CASE(test_case_get_loaded_cert),
    DSEC_TEST_CASE(test_case_get_loaded_cert_invalid),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Certificate API Tests",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
