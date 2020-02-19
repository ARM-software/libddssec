/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <test_manage_object_ca.h>
#include <dsec_errno.h>
#include <dsec_test.h>
#include <dsec_test_ta.h>
#include <dsec_test_canary.h>
#include <tee_client_api.h>
#include <string.h>

static void test_case_load_builtin(void)
{
    static const char name[] = "assets/cacert.pem";
    size_t name_size = sizeof(name)/sizeof(name[0]);
    TEEC_Result result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc(name_size*sizeof(char));
    strncpy(canaried_name, name, name_size);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 name_size,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
}

static void test_case_load_builtin_overload(void)
{
    static const char name[] = "assets/cacert.pem";
    size_t name_size = sizeof(name)/sizeof(name[0]);
    TEEC_Result result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc(name_size*sizeof(char));
    strncpy(canaried_name, name, name_size);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 strlen(canaried_name)+1,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 strlen(canaried_name)+1,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_ERROR_ITEM_NOT_FOUND);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
}

/*
 * Attempts to load cacert.pem (with a mis-spelling) so it tries to load an
 * objet that does not exist
 */
static void test_case_load_builtin_miss(void)
{
    static const char name[] = "carrot";
    size_t name_size = sizeof(name)/sizeof(name[0]);
    TEEC_Result result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc(name_size*sizeof(char));
    strncpy(canaried_name, name, name_size);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 name_size,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_ERROR_ITEM_NOT_FOUND);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
}

static void test_case_load_storage_miss(void)
{
    static const char name[] = "carrot";
    size_t name_size = strlen(name)+1;
    TEEC_Result result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc(name_size*sizeof(char));
    strncpy(canaried_name, name, name_size);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = load_object_storage(canaried_name,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_ERROR_ITEM_NOT_FOUND);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
}

static void test_case_unload_builtin(void)
{
    static const char name[] = "assets/cacert.pem";
    size_t name_size = sizeof(name)/sizeof(name[0]);
    TEEC_Result result = 0;

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc(name_size*sizeof(char));
    strncpy(canaried_name, name, name_size);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 strlen(canaried_name)+1,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = unload_object(&instance);
    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = load_object_builtin(canaried_name,
                                 strlen(canaried_name)+1,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    /* Only for clean-up, not checked for success */
    delete_persistent_object(canaried_name,
                             strlen(canaried_name)+1,
                             &instance);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
}

/* Create a file in secure storage, then load it */
static void test_case_create_persistent(void)
{
    char* name = "taro";
    int32_t result = 0;
    uint8_t object[] = {0xA, 0xD, 0xA, 0x5, 0x0, 0xB, 0x0, 0xE};

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc((strlen(name)+1)*sizeof(char));
    strncpy(canaried_name, name, strlen(name)+1);

    uint8_t* canaried_object = dsec_test_canary_alloc(sizeof(object));
    memcpy(canaried_object, object, sizeof(object));

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = create_persistent_object(canaried_object,
                                      sizeof(canaried_object),
                                      canaried_name,
                                      strlen(canaried_name)+1,
                                      &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = load_object_storage(canaried_name,
                                 &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    /* Only for clean-up, not checked for success */
    delete_persistent_object(canaried_name,
                             strlen(canaried_name)+1,
                             &instance);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
    dsec_test_canary_check(canaried_object);
    dsec_test_canary_free(canaried_object);
}

/* Try to create a file in secure storage using a name that is already taken */
static void test_case_create_persistent_same_name(void)
{
    char* name = "radish";
    uint32_t result = 0;
    uint8_t object[] = {0xA, 0xD, 0xA, 0x5, 0x0, 0xB, 0x0, 0xE};

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc((strlen(name)+1)*sizeof(char));
    strncpy(canaried_name, name, strlen(name)+1);

    uint8_t* canaried_object = dsec_test_canary_alloc(sizeof(object));
    memcpy(canaried_object, object, sizeof(object));

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = create_persistent_object(canaried_object,
                                      sizeof(canaried_object),
                                      canaried_name,
                                      strlen(canaried_name)+1,
                                      &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = create_persistent_object(canaried_object,
                                      sizeof(canaried_object),
                                      canaried_name,
                                      strlen(canaried_name)+1,
                                      &instance);

    /* Already taken */
    DSEC_TEST_ASSERT(result != TEEC_SUCCESS);

    /* Only for clean-up, not checked for success */
    delete_persistent_object(canaried_name,
                             strlen(canaried_name)+1,
                             &instance);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
    dsec_test_canary_check(canaried_object);
    dsec_test_canary_free(canaried_object);
}

/* Delete a file from secure storage */
/* All the 'create_persistent_object' tests also use 'delete_persistent_object'
 * but only these tests check for success
 */
static void test_case_delete_persistent(void)
{
    char* name = "caraway";
    uint32_t result = 0;
    uint8_t object[] = {0xA, 0xD, 0xA, 0x5, 0x0, 0xB, 0x0, 0xE};

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc((strlen(name)+1)*sizeof(char));
    strncpy(canaried_name, name, strlen(name)+1);

    uint8_t* canaried_object = dsec_test_canary_alloc(sizeof(object));
    memcpy(canaried_object, object, sizeof(object));

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = create_persistent_object(canaried_object,
                                      sizeof(canaried_object),
                                      canaried_name,
                                      strlen(canaried_name)+1,
                                      &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = delete_persistent_object(canaried_name,
                                      strlen(canaried_name)+1,
                                      &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = load_object_storage(canaried_name,
                                 &instance);

    /* It doesn't exist anymore */
    DSEC_TEST_ASSERT(result == TEEC_ERROR_ITEM_NOT_FOUND);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
    dsec_test_canary_check(canaried_object);
    dsec_test_canary_free(canaried_object);
}

/* Try to delete a file from secure storage that doesn't exist */
static void test_case_delete_persistent_miss(void)
{
    char* name = "shallot";
    char* wrong_name = "not shallot";
    uint32_t result = 0;
    uint8_t object[] = {0xA, 0xD, 0xA, 0x5, 0x0, 0xB, 0x0, 0xE};

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc((strlen(name)+1)*sizeof(char));
    strncpy(canaried_name, name, strlen(name)+1);

    char* canaried_wrong_name =
        dsec_test_canary_alloc((strlen(wrong_name)+1)*sizeof(char));
    strncpy(canaried_wrong_name, wrong_name, strlen(wrong_name)+1);

    uint8_t* canaried_object = dsec_test_canary_alloc(sizeof(object));
    memcpy(canaried_object, object, sizeof(object));

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = create_persistent_object(canaried_object,
                                      sizeof(canaried_object),
                                      canaried_name,
                                      strlen(canaried_name)+1,
                                      &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = delete_persistent_object(canaried_wrong_name,
                                      strlen(canaried_wrong_name)+1,
                                      &instance);

    DSEC_TEST_ASSERT(result == TEEC_ERROR_ITEM_NOT_FOUND);

    result = load_object_storage(canaried_name,
                                 &instance);

    /* It's still there */
    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    /* Only for clean-up, not checked for success */
    delete_persistent_object(canaried_name,
                             strlen(canaried_name)+1,
                             &instance);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
    dsec_test_canary_check(canaried_wrong_name);
    dsec_test_canary_free(canaried_wrong_name);
    dsec_test_canary_check(canaried_object);
    dsec_test_canary_free(canaried_object);
}

/* Delete files from secure storage using different names */
static void test_case_delete_persistent_different_names(void)
{
    char* name = "yam";
    char* next_name = "not yam";
    uint32_t result = 0;
    uint8_t object[] = {0xA, 0xD, 0xA, 0x5, 0x0, 0xB, 0x0, 0xE};

    TEEC_Session session;
    TEEC_Context context;

    struct dsec_instance instance = dsec_ca_instance_create(&session, &context);

    char* canaried_name = dsec_test_canary_alloc((strlen(name)+1)*sizeof(char));
    strncpy(canaried_name, name, strlen(name)+1);

    char* canaried_next_name =
        dsec_test_canary_alloc((strlen(next_name)+1)*sizeof(char));
    strncpy(canaried_next_name, next_name, strlen(next_name)+1);

    uint8_t* canaried_object = dsec_test_canary_alloc(sizeof(object));
    memcpy(canaried_object, object, sizeof(object));

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance) == TEEC_SUCCESS);

    result = create_persistent_object(canaried_object,
                                      sizeof(canaried_object),
                                      canaried_name,
                                      strlen(canaried_name)+1,
                                      &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = create_persistent_object(canaried_object,
                                      sizeof(canaried_object),
                                      canaried_next_name,
                                      strlen(canaried_next_name),
                                      &instance);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    result = delete_persistent_object(canaried_name,
                                      strlen(canaried_name)+1,
                                      &instance);

    result = delete_persistent_object(canaried_next_name,
                                      strlen(canaried_next_name),
                                      &instance);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
    dsec_test_canary_check(canaried_next_name);
    dsec_test_canary_free(canaried_next_name);
    dsec_test_canary_check(canaried_object);
    dsec_test_canary_free(canaried_object);
}

/* Create a file in one instance then delete it in another instance */
static void test_case_delete_persistent_instance_independence(void)
{
    char* name = "burdock";
    uint32_t result = 0;
    uint8_t object[] = {0xA, 0xD, 0xA, 0x5, 0x0, 0xB, 0x0, 0xE};

    TEEC_Session session1;
    TEEC_Context context1;
    TEEC_Session session2;
    TEEC_Context context2;

    struct dsec_instance instance1 =
        dsec_ca_instance_create(&session1, &context1);
    struct dsec_instance instance2 =
        dsec_ca_instance_create(&session2, &context2);

    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance1) == DSEC_SUCCESS);
    DSEC_TEST_ASSERT(dsec_ca_instance_open(&instance2) == DSEC_SUCCESS);

    /* +1 for \n */
    size_t name_length = strlen(name)+1;

    char* canaried_name = dsec_test_canary_alloc((name_length)*sizeof(char));
    strncpy(canaried_name, name, name_length);

    uint8_t* canaried_object = dsec_test_canary_alloc(sizeof(object));
    memcpy(canaried_object, object, sizeof(object));

    result = create_persistent_object(canaried_object,
                                      sizeof(canaried_object),
                                      canaried_name,
                                      name_length,
                                      &instance1);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance1) == TEEC_SUCCESS);

    result = create_persistent_object(canaried_object,
                                      sizeof(canaried_object),
                                      canaried_name,
                                      name_length,
                                      &instance2);

    /* Can't create another file over the original file */
    DSEC_TEST_ASSERT(result != TEEC_SUCCESS);

    result = delete_persistent_object(canaried_name,
                                      name_length,
                                      &instance2);

    DSEC_TEST_ASSERT(result == TEEC_SUCCESS);

    DSEC_TEST_ASSERT(dsec_ca_instance_close(&instance2) == TEEC_SUCCESS);
    dsec_test_canary_check(canaried_name);
    dsec_test_canary_free(canaried_name);
    dsec_test_canary_check(canaried_object);
    dsec_test_canary_free(canaried_object);
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_load_builtin),
    DSEC_TEST_CASE(test_case_load_builtin_overload),
    DSEC_TEST_CASE(test_case_load_builtin_miss),
    DSEC_TEST_CASE(test_case_load_storage_miss),
    DSEC_TEST_CASE(test_case_unload_builtin),
    DSEC_TEST_CASE(test_case_create_persistent),
    DSEC_TEST_CASE(test_case_create_persistent_same_name),
    DSEC_TEST_CASE(test_case_delete_persistent),
    DSEC_TEST_CASE(test_case_delete_persistent_miss),
    DSEC_TEST_CASE(test_case_delete_persistent_different_names),
    DSEC_TEST_CASE(test_case_delete_persistent_instance_independence)
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Manage secure objects",
    .test_case_count = sizeof(test_case_table)/sizeof(test_case_table[0]),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup,
    .test_suite_teardown = dsec_test_ta_teardown,
};
