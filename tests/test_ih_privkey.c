/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ih.h>
#include <dsec_ih_ca.h>
#include <dsec_ih_cert.h>
#include <dsec_ih_privkey.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_util.h>
#include <dsec_errno.h>
#include <string.h>

static void test_case_load_privkey(void)
{
    static const char ca[] = "assets/cacert.pem";
    static const char cert[] = "assets/p1cert.pem";
    static const char privkey[] = "assets/p1privkey.pem";
    static const char password[] = "";
    uint32_t password_size = 0;

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    /* Try load with no opened instance */
    result = dsec_ih_privkey_load(&instance,
                                  handle,
                                  privkey,
                                  password,
                                  password_size);

    DSEC_TEST_ASSERT(result != DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    /* Try load with no identity handle */
    result = dsec_ih_privkey_load(&instance,
                                  handle,
                                  privkey,
                                  password,
                                  password_size);

    DSEC_TEST_ASSERT(result != DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    /* try load no CA */
    result = dsec_ih_privkey_load(&instance,
                                  handle,
                                  privkey,
                                  password,
                                  password_size);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Try load no certificate */
    result = dsec_ih_privkey_load(&instance,
                                  handle,
                                  privkey,
                                  password,
                                  password_size);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    result = dsec_ih_cert_load(&instance, handle, cert);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Try load which should success */
    result = dsec_ih_privkey_load(&instance,
                                  handle,
                                  privkey,
                                  password,
                                  password_size);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Try overload */
    result = dsec_ih_privkey_load(&instance,
                                  handle,
                                  privkey,
                                  password,
                                  password_size);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    result = dsec_ih_privkey_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    result = dsec_ih_ca_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_unload_privkey(void)
{
    static const char ca[] = "assets/cacert.pem";
    static const char cert[] = "assets/p1cert.pem";
    static const char privkey[] = "assets/p1privkey.pem";
    static const char password[] = "";
    uint32_t password_size = 0;

    int32_t handle = -1;
    int32_t result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    /* Try unload with no opened instance */
    DSEC_TEST_ASSERT(dsec_ih_privkey_unload(&instance, handle) != DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);

    /* Try unload with no identity handle */
    DSEC_TEST_ASSERT(dsec_ih_privkey_unload(&instance, handle) == DSEC_E_PARAM);

    DSEC_TEST_ASSERT(dsec_ih_create(&handle, &instance) == DSEC_SUCCESS);

    /* try unload no CA */
    DSEC_TEST_ASSERT(dsec_ih_privkey_unload(&instance, handle) == DSEC_E_DATA);

    result = dsec_ih_ca_load(&instance, handle, ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Try unload no certificate */
    DSEC_TEST_ASSERT(dsec_ih_privkey_unload(&instance, handle) == DSEC_E_DATA);

    result = dsec_ih_cert_load(&instance, handle, cert);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Try unload which should success */
    result = dsec_ih_privkey_load(&instance,
                                  handle,
                                  privkey,
                                  password,
                                  password_size);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_privkey_unload(&instance, handle) == DSEC_SUCCESS);
    /* Double unload should fail */
    DSEC_TEST_ASSERT(dsec_ih_privkey_unload(&instance, handle) == DSEC_E_DATA);

    result = dsec_ih_cert_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    result = dsec_ih_ca_unload(&instance, handle);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&instance, handle) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_load_and_sign(void)
{
    static const char name_ca[] = "assets/cacert.pem";
    static const char name_li[] = "assets/p1cert.pem";
    static const char name_pk[] = "assets/p1privkey.pem";

    int32_t lih = -1;
    int32_t result = 0;

    uint8_t buffer[1024];
    uint32_t buffer_size = DSEC_ARRAY_SIZE(buffer);
    uint8_t signature[128];
    uint32_t signature_size = DSEC_ARRAY_SIZE(signature);

    TEEC_Session session;
    TEEC_Context context;

    for (uint32_t i = 0; i < buffer_size; i++) {
        buffer[i] = i;
    }

    struct dsec_instance inst = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&inst) == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_create(&lih, &inst) == DSEC_SUCCESS);
    result = dsec_ih_ca_load(&inst, lih, name_ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_load(&inst, lih, name_li);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    result = dsec_ih_privkey_load(&inst, lih, name_pk, "", 0);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_privkey_sign(signature,
                                  &signature_size,
                                  &inst,
                                  lih,
                                  buffer,
                                  buffer_size);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_verify(&inst,
                                 lih,
                                 buffer,
                                 buffer_size,
                                 signature,
                                 signature_size);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_privkey_unload(&inst, lih) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_cert_unload(&inst, lih) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_ca_unload(&inst, lih) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&inst, lih) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&inst) == DSEC_SUCCESS);
}

static void test_case_load_and_sign_invalid(void)
{
    static const char name_ca[] = "assets/cacert.pem";
    static const char name_li[] = "assets/p1cert.pem";
    static const char name_pk[] = "assets/p1privkey.pem";

    int32_t lih = -1;
    int32_t result = 0;

    uint8_t buffer[1024];
    uint32_t buffer_size = DSEC_ARRAY_SIZE(buffer);
    uint8_t signature[128];
    uint32_t signature_size = DSEC_ARRAY_SIZE(signature);

    TEEC_Session session;
    TEEC_Context context;

    for (uint32_t i = 0; i < buffer_size; i++) {
        buffer[i] = i;
    }

    struct dsec_instance inst = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&inst) == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ih_create(&lih, &inst) == DSEC_SUCCESS);
    result = dsec_ih_ca_load(&inst, lih, name_ca);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_ih_cert_load(&inst, lih, name_li);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Try to sign before the private key is loaded */
    result = dsec_ih_privkey_sign(signature,
                                  &signature_size,
                                  &inst,
                                  lih,
                                  buffer,
                                  buffer_size);

    DSEC_TEST_ASSERT(result == DSEC_E_DATA);

    result = dsec_ih_privkey_load(&inst, lih, name_pk, "", 0);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    /* Try to sign with a signature buffer too small. */
    signature_size = 8;
    buffer_size = DSEC_ARRAY_SIZE(buffer);
    result = dsec_ih_privkey_sign(signature,
                                  &signature_size,
                                  &inst,
                                  lih,
                                  buffer,
                                  buffer_size);

    DSEC_TEST_ASSERT(result == DSEC_E_SHORT_BUFFER);

    DSEC_TEST_ASSERT(dsec_ih_privkey_unload(&inst, lih) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_cert_unload(&inst, lih) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_ca_unload(&inst, lih) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ih_delete(&inst, lih) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&inst) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_load_privkey),
    DSEC_TEST_CASE(test_case_unload_privkey),
    DSEC_TEST_CASE(test_case_load_and_sign),
    DSEC_TEST_CASE(test_case_load_and_sign_invalid),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Private Key API Tests",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
