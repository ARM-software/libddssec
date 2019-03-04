/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TEST_MANAGE_OBJECT_CA_H
#define TEST_MANAGE_OBJECT_CA_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

#include <dsec_ca.h>
#include <stdint.h>
#include <tee_client_api.h>

/* Invoke dsec_ta_load_builtin in the TA */
TEEC_Result load_object_builtin(const char* name,
                                size_t name_length,
                                struct dsec_instance* instance);

/* Invoke dsec_ta_unload_object_memory in the TA */
TEEC_Result unload_object(struct dsec_instance* instance);

#ifdef __cplusplus
}
#endif /*__cplusplus */

#endif /* TEST_MANAGE_OBJECT_CA_H */
