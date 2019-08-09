/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_hh_challenge.h>
#include <dsec_hh.h>
#include <dsec_hh_dh.h>
#include <dsec_key_material.h>
#include <dsec_ssh.h>
#include <dsec_errno.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_util.h>
#include <string.h>

#define DSEC_TRANSFORMATION_KIND_SIZE (4U)
#define DSEC_MASTER_SALT_SIZE (32U)
#define DSEC_SENDER_KEY_ID_SIZE (4U)
#define DSEC_MASTER_SENDER_KEY_SIZE (32U)
#define DSEC_RECEIVER_SPECIFIC_KEY_ID (4U)
#define DSEC_MASTER_RECEIVER_SPECIFIC_KEY_SIZE (32U)
#define DSEC_DH_PUBLIC_SIZE (256U)
#define DSEC_CHALLENGE_SIZE (32U)

static void test_case_key_material_create(void)
{
    const int32_t max_allocated_handle = 4;
    int32_t result = 0;
    int32_t km_handle_id = 0;
    bool use_gmac;
    bool use_256_bits;

    uint8_t transformation_kind[DSEC_TRANSFORMATION_KIND_SIZE];
    uint8_t master_salt[DSEC_MASTER_SALT_SIZE];
    uint8_t sender_key_id[DSEC_SENDER_KEY_ID_SIZE];
    uint8_t master_sender_key[DSEC_MASTER_SENDER_KEY_SIZE];
    uint8_t receiver_specific_key_id[DSEC_RECEIVER_SPECIFIC_KEY_ID];
    uint8_t
        master_receiver_specific_key[DSEC_MASTER_RECEIVER_SPECIFIC_KEY_SIZE];

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance inst = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&inst) == DSEC_SUCCESS);

    /* Try all possibilities for use_gmac and use_256_bits */
    for (int32_t i = 0; i < max_allocated_handle; i++) {
        /* i:            0     1     2     3     4     5
         * use_gmac:     true  false true  false true  false ...
         * use_256_bits: true  true  false false true  true  ...*/
        use_gmac = ((i % 2) == 0);
        use_256_bits = ((i % 4) < 2);

        result = dsec_key_material_create(&km_handle_id,
                                          &inst,
                                          use_gmac,
                                          use_256_bits);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(km_handle_id == i);

        result = dsec_key_material_return(transformation_kind,
                                          master_salt,
                                          sender_key_id,
                                          master_sender_key,
                                          receiver_specific_key_id,
                                          master_receiver_specific_key,
                                          &inst,
                                          km_handle_id);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    for (int32_t i = 0; i < max_allocated_handle; i++) {
        result = dsec_key_material_delete(&inst, i);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&inst) == DSEC_SUCCESS);
}

static void test_case_key_material_create_delete(void)
{
    const int32_t max_allocated_handle = 4;
    int32_t result = 0;
    int32_t km_handle_id = 0;
    bool use_gmac = false;
    bool use_256_bits = true;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance inst = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&inst) == DSEC_SUCCESS);

    for (int32_t i = 0; i < max_allocated_handle; i++) {
        result = dsec_key_material_create(&km_handle_id,
                                          &inst,
                                          use_gmac,
                                          use_256_bits);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(km_handle_id == 0);

        result = dsec_key_material_delete(&inst, km_handle_id);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&inst) == DSEC_SUCCESS);
}

static void test_case_key_material_generate_copy(void)
{
    TEEC_Session session;
    TEEC_Context context;

    int32_t hh_h = -1;
    int32_t result = 0;
    int32_t ss_h = -1;
    int32_t km_h = -1;
    int32_t km_h_copy = -1;

    uint8_t dh_public[DSEC_DH_PUBLIC_SIZE];
    uint8_t challenge2[DSEC_CHALLENGE_SIZE];

    uint8_t transformation_kind[DSEC_TRANSFORMATION_KIND_SIZE];
    uint8_t master_salt[DSEC_MASTER_SALT_SIZE];
    uint8_t sender_key_id[DSEC_SENDER_KEY_ID_SIZE];
    uint8_t master_sender_key[DSEC_MASTER_SENDER_KEY_SIZE];
    uint8_t receiver_specific_key_id[DSEC_RECEIVER_SPECIFIC_KEY_ID];
    uint8_t
        master_receiver_specific_key[DSEC_MASTER_RECEIVER_SPECIFIC_KEY_SIZE];

    uint8_t transformation_kind_copy[DSEC_TRANSFORMATION_KIND_SIZE];
    uint8_t master_salt_copy[DSEC_MASTER_SALT_SIZE];
    uint8_t sender_key_id_copy[DSEC_SENDER_KEY_ID_SIZE];
    uint8_t master_sender_key_copy[DSEC_MASTER_SENDER_KEY_SIZE];
    uint8_t receiver_specific_key_id_copy[DSEC_RECEIVER_SPECIFIC_KEY_ID];
    uint8_t master_receiver_specific_key_copy
        [DSEC_MASTER_RECEIVER_SPECIFIC_KEY_SIZE];

    for (uint32_t i = 0; i < DSEC_CHALLENGE_SIZE; i++) {
        challenge2[i] = i;
    }

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_hh_create(&hh_h, &instance)  == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_hh_dh_generate(&instance, hh_h) == DSEC_SUCCESS);

    result = dsec_hh_dh_set_public(&instance,
                                   hh_h,
                                   dh_public,
                                   DSEC_DH_PUBLIC_SIZE);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_hh_challenge_generate(&instance,
                                        hh_h,
                                        DSEC_CHALLENGE_SIZE,
                                        1);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_hh_challenge_set(&instance,
                                   hh_h,
                                   challenge2,
                                   DSEC_CHALLENGE_SIZE,
                                   2);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ssh_derive(&ss_h, &instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(ss_h == 0);

    result = dsec_key_material_generate(&km_h, &instance, ss_h);
    DSEC_TEST_ASSERT(km_h == 0);

    result = dsec_key_material_copy(&km_h_copy, &instance, km_h);
    DSEC_TEST_ASSERT(km_h_copy == 1);

    result = dsec_key_material_return(transformation_kind,
                                      master_salt,
                                      sender_key_id,
                                      master_sender_key,
                                      receiver_specific_key_id,
                                      master_receiver_specific_key,
                                      &instance,
                                      km_h);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);

    result = dsec_key_material_return(transformation_kind_copy,
                                      master_salt_copy,
                                      sender_key_id_copy,
                                      master_sender_key_copy,
                                      receiver_specific_key_id_copy,
                                      master_receiver_specific_key_copy,
                                      &instance,
                                      km_h_copy);

    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(km_h_copy == 1);

    DSEC_TEST_ASSERT(memcmp(transformation_kind_copy,
                            transformation_kind,
                            sizeof(transformation_kind)) == 0);

    DSEC_TEST_ASSERT(memcmp(master_salt_copy,
                            master_salt,
                            sizeof(master_salt)) == 0);

    DSEC_TEST_ASSERT(memcmp(sender_key_id_copy,
                            sender_key_id,
                            sizeof(sender_key_id)) == 0);

    DSEC_TEST_ASSERT(memcmp(master_sender_key_copy,
                            master_sender_key,
                            sizeof(master_sender_key)) == 0);

    DSEC_TEST_ASSERT(memcmp(receiver_specific_key_id_copy,
                            receiver_specific_key_id,
                            sizeof(receiver_specific_key_id)) == 0);

    DSEC_TEST_ASSERT(memcmp(master_receiver_specific_key_copy,
                            master_receiver_specific_key,
                            sizeof(master_receiver_specific_key)) == 0);

    result = dsec_key_material_delete(&instance, km_h_copy);
    DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_key_material_delete(&instance, km_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_hh_delete(&instance, hh_h) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == DSEC_SUCCESS);
}

static void test_case_key_material_register(void)
{
    const int32_t max_allocated_handle = 4;
    int32_t result = 0;
    int32_t km_handle_id = 0;
    int32_t km_handle_id_register = 0;
    bool use_gmac = false;
    bool use_256_bits = true;
    bool is_origin_auth = false;
    bool generate_receiver_specific_key = false;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance inst = dsec_ca_instance_create(&session, &context);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&inst) == DSEC_SUCCESS);

    /* Try all possibilities for use_gmac and use_256_bits */
    for (int32_t i = 0; i < max_allocated_handle; i++) {
        use_gmac = ((i % 2) == 0);
        use_256_bits = ((i % 4) < 2);

        result = dsec_key_material_create(&km_handle_id,
                                          &inst,
                                          use_gmac,
                                          use_256_bits);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
        DSEC_TEST_ASSERT(km_handle_id == i*2);

        is_origin_auth = ((i % 2) == 0);
        generate_receiver_specific_key = ((i % 4) < 2);
        result = dsec_key_material_register(&km_handle_id_register,
                                            &inst,
                                            km_handle_id,
                                            is_origin_auth,
                                            generate_receiver_specific_key);

        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    for (int32_t i = 0; i < max_allocated_handle; i++) {
        result = dsec_key_material_delete(&inst, i);
        DSEC_TEST_ASSERT(result == DSEC_SUCCESS);
    }

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&inst) == DSEC_SUCCESS);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_key_material_create),
    DSEC_TEST_CASE(test_case_key_material_create_delete),
    DSEC_TEST_CASE(test_case_key_material_generate_copy),
    DSEC_TEST_CASE(test_case_key_material_register),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Key material tests",
    .test_case_count = DSEC_ARRAY_SIZE(test_case_table),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
