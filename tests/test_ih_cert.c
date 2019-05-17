/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <builtins/builtins_list.h>
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

static void test_case_get_subject_name(void)
{
    static const char ca[] = "cacert.pem";
    static const char cert_valid[] = "p1cert.pem";

    int32_t handle = -1;
    uint8_t output_sn[2048] = {0};
    uint32_t output_sn_size = DSEC_ARRAY_SIZE(output_sn);
    static const char expected_sn[] = "C=UK, ST=CB, O=Arm, "
                                      "CN=libddssecApplication, "
                                      "emailAddress=application@arm.com";

    uint32_t expected_sn_size = DSEC_ARRAY_SIZE(expected_sn);
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

    result = dsec_ih_cert_get_sn(output_sn, &output_sn_size, &instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(output_sn_size == expected_sn_size);
    DSEC_TEST_ASSERT(
        memcmp((char*)output_sn, expected_sn, expected_sn_size) == 0);

    DSEC_TEST_ASSERT(dsec_ih_cert_unload(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_ca_unload(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_get_signature(void)
{
    static const char ca[] = "cacert.pem";
    static const char cert_valid[] = "p1cert.pem";

    int32_t handle = -1;

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

    result = dsec_ih_cert_load(&instance, handle, cert_valid);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_get_signature_algorithm(output_sign_algo,
                                                  &output_sign_algo_size,
                                                  &instance,
                                                  handle);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(output_sign_algo_size == expected_sign_algo_size);
    DSEC_TEST_ASSERT(memcmp((char*)output_sign_algo,
                            expected_sign_algo,
                            expected_sign_algo_size) == 0);

    DSEC_TEST_ASSERT(dsec_ih_cert_unload(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_ca_unload(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_invalid_get_subject_name(void)
{
    static const char ca[] = "cacert.pem";
    static const char cert_valid[] = "p1cert.pem";

    uint8_t output_sn[128] = {0};
    uint32_t output_sn_size = DSEC_ARRAY_SIZE(output_sn);

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    /* Check for NULL input */
    result = dsec_ih_cert_get_sn(output_sn, NULL, &instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Check for short buffer */
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);
    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_load(&instance, handle, cert_valid);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_get_sn(output_sn,
                                 &output_sn_size,
                                 &instance,
                                 handle);

    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);
    DSEC_TEST_ASSERT(output_sn_size == 0U);

    DSEC_TEST_ASSERT(dsec_ih_cert_unload(&instance, handle) == DSEC_SUCCESS);

    /* Certificate is not loaded anymore. */
    output_sn_size = DSEC_ARRAY_SIZE(output_sn);
    result = dsec_ih_cert_get_sn(output_sn, &output_sn_size, &instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_E_DATA);
    DSEC_TEST_ASSERT(output_sn_size == 0U);

    DSEC_TEST_ASSERT(dsec_ih_ca_unload(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_invalid_get_signature(void)
{
    static const char ca[] = "cacert.pem";
    static const char cert_valid[] = "p1cert.pem";

    uint8_t output_sign_algo[4] = {0};
    uint32_t output_sign_algo_size = DSEC_ARRAY_SIZE(output_sign_algo);

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    /* Check for NULL input */
    result = dsec_ih_cert_get_signature_algorithm(output_sign_algo,
                                                  NULL,
                                                  &instance,
                                                  handle);

    DSEC_TEST_ASSERT(result == DSEC_E_PARAM);

    /* Check for short buffer */
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_load(&instance, handle, cert_valid);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_get_signature_algorithm(output_sign_algo,
                                                  &output_sign_algo_size,
                                                  &instance,
                                                  handle);

    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);
    DSEC_TEST_ASSERT(output_sign_algo_size == 0);

    DSEC_TEST_ASSERT(dsec_ih_cert_unload(&instance, handle) == DSEC_SUCCESS);

    /* Certificate is not loaded anymore. */
    output_sign_algo_size = DSEC_ARRAY_SIZE(output_sign_algo);
    result = dsec_ih_cert_get_signature_algorithm(output_sign_algo,
                                                  &output_sign_algo_size,
                                                  &instance,
                                                  handle);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);
    DSEC_TEST_ASSERT(output_sign_algo_size == 0);

    DSEC_TEST_ASSERT(dsec_ih_ca_unload(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_load_get_store_cert(void)
{
    static const char ca[] = "cacert.pem";
    static const char cert[] = "p1cert.pem";

    uint8_t output_certificate[2048] = {0};
    uint32_t output_certificate_size = DSEC_ARRAY_SIZE(output_certificate);

    uint8_t output_certificate2[2048] = {0};
    uint32_t output_certificate2_size = DSEC_ARRAY_SIZE(output_certificate2);

    int32_t lih = -1;
    int32_t rih = -1;

    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&lih, &instance) == DSEC_SUCCESS);

    result = dsec_ih_ca_load(&instance, lih, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_load(&instance, lih, cert);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_get(output_certificate,
                              &output_certificate_size,
                              &instance,
                              lih);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_create(&rih, &instance) == TEEC_SUCCESS);

    result = dsec_ih_cert_load_from_buffer(&instance,
                                           rih,
                                           output_certificate,
                                           output_certificate_size,
                                           lih);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_get(output_certificate2,
                              &output_certificate2_size,
                              &instance,
                              rih);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(memcmp(output_certificate2,
                            output_certificate,
                            output_certificate2_size) == 0);

    result = dsec_ih_cert_unload(&instance, lih);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    result = dsec_ih_cert_unload(&instance, rih);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_ca_unload(&instance, lih);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    result = dsec_ih_ca_unload(&instance, rih);
    DSEC_TEST_ASSERT(result != DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, lih) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, rih) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_load_get_store_cert_invalid(void)
{
    static const char ca[] = "cacert.pem";
    static const char cert[] = "p1cert.pem";

    const uint8_t* const cert_invalid[] = {
        invalid_nosignature_cert_pem,
        invalid_p1_cert_shortterm_signed_pem,
        invalid_signature_cert_pem,
        p1privkey_pem,
    };

    int32_t lih = -1;
    int32_t rih = -1;

    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&lih, &instance) == DSEC_SUCCESS);
    result = dsec_ih_ca_load(&instance, lih, ca);
    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);
    result = dsec_ih_cert_load(&instance, lih, cert);
    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_create(&rih, &instance) == DSEC_SUCCESS);

    for (size_t i = 0U; i < DSEC_ARRAY_SIZE(cert_invalid); i++) {
        result = dsec_ih_cert_load_from_buffer(
            &instance,
            rih,
            cert_invalid[i],
            strlen((char*) cert_invalid[i]) + 1,
            lih);

        DSEC_TEST_ASSERT(result != DSEC_SUCCESS);
    }

    result = dsec_ih_cert_unload(&instance, lih);
    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);
    result = dsec_ih_cert_unload(&instance, rih);
    DSEC_TEST_ASSERT(result != TEEC_SUCCESS);

    result = dsec_ih_ca_unload(&instance, lih);
    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);
    result = dsec_ih_ca_unload(&instance, rih);
    DSEC_TEST_ASSERT(result != TEEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, lih) == TEEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, rih) == TEEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_load_cert_from_builtin),
    DSEC_TEST_CASE(test_case_invalid_load_cert),
    DSEC_TEST_CASE(test_case_get_loaded_cert),
    DSEC_TEST_CASE(test_case_get_loaded_cert_invalid),
    DSEC_TEST_CASE(test_case_get_subject_name),
    DSEC_TEST_CASE(test_case_get_signature),
    DSEC_TEST_CASE(test_case_invalid_get_subject_name),
    DSEC_TEST_CASE(test_case_invalid_get_signature),
    DSEC_TEST_CASE(test_case_load_get_store_cert),
    DSEC_TEST_CASE(test_case_load_get_store_cert_invalid),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Certificate API Tests",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
