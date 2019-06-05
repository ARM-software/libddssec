/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "../builtins/builtins_list.h"
#include <dsec_ta_manage_object.h>
#include <dsec_util.h>
#include <user_ta_header_defines.h>
#include <tee_internal_api.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Temporarily stored object */
struct object_handle_t {
    size_t size;
    bool is_set;
    uint8_t data[DSEC_OBJECT_DATA_MAX_SIZE];
} object_memory;

/* Copies data to the object memory */
static TEE_Result object_memory_set(uint8_t data[DSEC_OBJECT_DATA_MAX_SIZE],
                                    size_t size)
{
    TEE_Result result = 0;

    if (data != NULL) {
        if (!object_memory.is_set && (size <= DSEC_OBJECT_DATA_MAX_SIZE)) {
            TEE_MemMove(object_memory.data, data, size);
            object_memory.is_set = true;
            object_memory.size = size;
            result = TEE_SUCCESS;
            DMSG("Setting object memory");
        } else {
            EMSG("There is already an object loaded");
            result = TEE_ERROR_OUT_OF_MEMORY;
        }
    } else {
        EMSG("Object is NULL");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

void dsec_ta_unload_object_memory(void)
{
    /* Return value is always &(object_memory.data), so is unused */
    (void) memset((void*)&(object_memory.data),
                           0x0,
                           DSEC_ARRAY_SIZE(object_memory.data));

    DMSG("Clearing object memory");
    object_memory.is_set = false;
    object_memory.size = 0;
}

TEE_Result dsec_ta_load_builtin(void** buffer,
                                size_t* size,
                                const char name[DSEC_MAX_NAME_LENGTH])
{
    TEE_Result result = 0;
    bool set = false;

    /* Declared in <builtins/builtins.h>. Generated at build-time */
    size_t num_builtin = DSEC_ARRAY_SIZE(builtin_objects);

    if ((buffer != NULL) && (size != NULL)) {
        for (size_t i = 0; i < num_builtin; i++) {
            if (memcmp(name,
                       builtin_objects[i].name,
                       (strlen(builtin_objects[i].name) + 1)) == 0) {

                result = object_memory_set(
                            (uint8_t*)builtin_objects[i].builtin,
                            builtin_objects[i].size);

                if (result == TEE_SUCCESS) {
                    set = true;
                    DMSG("Builtin object loaded");
                    *buffer = (void*)&object_memory.data;
                    *size = object_memory.size;
                } else {
                    *buffer = NULL;
                    *size = 0;
                    /* Error handled below if no names match */
                }
                break;
            }
        }
    } else {
        EMSG("Invalid parameters for loading an object");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    if (!set) {
        DMSG("Object name not in builtins");
        result = TEE_ERROR_ITEM_NOT_FOUND;
    }
    return result;
}

#if DSEC_TEST
TEE_Result dsec_ta_test_load_object_builtin(uint32_t parameters_type,
                                            const TEE_Param parameters[1])
{
    TEE_Result result = 0;

    uint32_t expected_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, /* Name */
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {

        void* object_buffer = NULL;
        size_t object_size = 0;

        result = dsec_ta_load_builtin(&object_buffer,
                                      &object_size,
                                      parameters[0].memref.buffer);

        if (result != TEE_SUCCESS) {
            /* Failing result is returned */
            EMSG("Could not load the object");
        } else {
            DMSG("Object size: %zd", object_size);
        }
    } else {
        EMSG("Invalid parameters for loading an object");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_test_unload_object(void)
{
    TEE_Result result = 0;
    dsec_ta_unload_object_memory();
    result = TEE_SUCCESS;

    for (size_t i = 0; i < DSEC_OBJECT_DATA_MAX_SIZE; i++) {
        if (object_memory.data[i] != 0x0) {
            result = TEE_ERROR_BAD_STATE;
        }
    }

    return result;
}
#endif /* DSEC_TEST */
