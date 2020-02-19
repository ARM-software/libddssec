/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "../builtins/builtins_list.h"
#include <dsec_ta_manage_object.h>
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
                           sizeof(object_memory.data));

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
    size_t num_builtin = sizeof(builtin_objects)/sizeof(builtin_objects[0]);

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

TEE_Result dsec_ta_load_storage(void** buffer,
                                size_t* size,
                                const char name[DSEC_MAX_NAME_LENGTH])
{
    TEE_Result result = 0;
    if (name != NULL) {
        /* 1 is used because it's the size of an empty string with a newline */
        size_t name_size = strnlen(name, DSEC_MAX_NAME_LENGTH);
        if (name_size > 1 && name_size <= DSEC_MAX_NAME_LENGTH) {
            char local_name[DSEC_MAX_NAME_LENGTH] = {0};
            TEE_ObjectHandle object = 0;
            uint32_t object_data_flags = TEE_DATA_FLAG_ACCESS_READ |
                                         TEE_DATA_FLAG_SHARE_READ;

            TEE_MemMove(local_name, name, name_size);
            result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                              local_name,
                                              name_size,
                                              object_data_flags,
                                              &object);

            if (result == TEE_SUCCESS) {
                TEE_ObjectInfo object_info;
                result = TEE_GetObjectInfo1(object, &object_info);
                if (result == (TEE_Result)TEE_SUCCESS) {
                    uint32_t read = 0; /* The number of bytes read */
                    result = TEE_ReadObjectData(object,
                                                object_memory.data,
                                                object_info.dataSize,
                                                &read);

                    TEE_CloseObject(object);
                    if ((result == TEE_SUCCESS) &&
                        (read == object_info.dataSize)) {

                        DMSG("Stored object loaded");
                        *buffer = (void*)&object_memory.data;
                        *size = object_info.dataSize;
                    } else {
                        EMSG("Could not read from the object."
                             "Read %d bytes and result is %d",
                             read,
                             result);
                    }
                } else {
                    TEE_CloseObject(object);
                    EMSG("Could not get information for the object. "
                         "Result is %d",
                         result);

                    result = TEE_ERROR_ACCESS_DENIED;
                }
            } else {
                EMSG("Could not open the object. Result is %x", result);
                result = TEE_ERROR_ITEM_NOT_FOUND;
            }
        } else {
            EMSG("Bad object name length: %zd.", name_size);
            result = TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        EMSG("Invalid parameters for loading the object from secure storage");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result create_persistent_object(const char name[DSEC_MAX_NAME_LENGTH],
                                    void* buffer,
                                    size_t size)
{
    TEE_Result result = 0;

    if ((name != NULL) &&
        (size > 0) &&
        (buffer != NULL)) {

        size_t name_size = strnlen(name, DSEC_MAX_NAME_LENGTH);
        /* 1 is used because it's the size of an empty string with a newline */
        if (name_size > 1 && name_size <= DSEC_MAX_NAME_LENGTH) {
            TEE_ObjectHandle object;

            uint32_t object_data_flags = TEE_DATA_FLAG_ACCESS_READ |
                                         TEE_DATA_FLAG_ACCESS_WRITE |
                                         TEE_DATA_FLAG_ACCESS_WRITE_META |
                                         TEE_DATA_FLAG_SHARE_READ |
                                         TEE_DATA_FLAG_SHARE_WRITE;

            result =
                TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                           name,
                                           name_size,
                                           object_data_flags,
                                           /* Attributes, not set */
                                           TEE_HANDLE_NULL,
                                           buffer,
                                           size,
                                           &object);

            if (result == TEE_SUCCESS) {
                TEE_CloseObject(object);
            } else {
                EMSG("Could not create a persistent object, error: %x",
                     result);
                result = TEE_ERROR_STORAGE_NOT_AVAILABLE;
            }
        } else {
            EMSG("Bad object name length: %zd.", name_size);
            result = TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        EMSG("Invalid parameters for writing an object to secure storage");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result delete_persistent_object(const char name[DSEC_MAX_NAME_LENGTH])
{
    TEE_Result result = 0;
    size_t name_size = strnlen(name, DSEC_MAX_NAME_LENGTH);
    /* 1 is used because it's the size of an empty string with a newline */
    if ((name != NULL) &&
        (name_size > 1)) {

        TEE_ObjectHandle object;
        uint32_t object_data_flags = TEE_DATA_FLAG_ACCESS_READ |
                                     TEE_DATA_FLAG_ACCESS_WRITE |
                                     TEE_DATA_FLAG_ACCESS_WRITE_META |
                                     TEE_DATA_FLAG_SHARE_READ |
                                     TEE_DATA_FLAG_SHARE_WRITE;

        result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                          name,
                                          name_size,
                                          object_data_flags,
                                          &object);

        if (result == TEE_SUCCESS) {
            result = TEE_CloseAndDeletePersistentObject1(object);

            if (result != TEE_SUCCESS) {
                if (result == TEE_ERROR_STORAGE_NOT_AVAILABLE) {
                    EMSG("Could not delete the object as it doesn't exist");
                } else {
                    EMSG("Could not delete the object. Result is %d",
                         result);

                    result = TEE_ERROR_BAD_STATE;
                }
            }
        } else if (result == TEE_ERROR_ITEM_NOT_FOUND) {
            EMSG("Could not open the object as it doesn't exist");
            /* Let the result bubble-up */
        } else {
            EMSG("Could not access the object. Result is %d", result);
            result = TEE_ERROR_ACCESS_DENIED;
        }
    } else {
        EMSG("Invalid parameters for writing an object to secure storage");
        result = TEE_ERROR_BAD_PARAMETERS;
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

TEE_Result dsec_ta_test_load_object_storage(uint32_t parameters_type,
                                            const TEE_Param parameters[1])
{
    TEE_Result result = 0;

    uint32_t expected_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, /* Name */
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if ((parameters_type == expected_types) &&
        (parameters != NULL) &&
        ((int32_t)parameters[0].memref.size > 0) &&
        (parameters[0].memref.buffer != NULL)) {

        void* object_buffer = NULL;
        size_t object_size = 0;

        result = dsec_ta_load_storage(&object_buffer,
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

TEE_Result dsec_ta_test_create_persistent_object(
    uint32_t parameters_type,
    const TEE_Param parameters[2])
{
    TEE_Result result = 0;
    uint32_t expected_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, /* Data */
        TEE_PARAM_TYPE_MEMREF_INPUT, /* Name */
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if ((parameters_type == expected_types) &&
        (parameters != NULL) &&
        ((int32_t)parameters[0].memref.size > 0) &&
        (parameters[0].memref.buffer != NULL) &&
        (parameters[1].memref.buffer != NULL) &&
        (parameters[1].memref.size > 1) &&
        (parameters[1].memref.size <= (uint32_t)DSEC_MAX_NAME_LENGTH)) {

        size_t name_size = (size_t)parameters[1].memref.size;
        char name[DSEC_MAX_NAME_LENGTH] = {0};

        const char* move_result = TEE_MemMove(name,
                                              parameters[1].memref.buffer,
                                              (uint32_t)name_size);

        if (move_result == name) {
            result = create_persistent_object(
                         name,
                         parameters[0].memref.buffer,
                         (size_t)parameters[0].memref.size);

            if (result != TEE_SUCCESS) {
                EMSG("Could not create the object in secure storage");
            }
        } else {
            EMSG("Name was not moved");
            result = TEE_ERROR_OUT_OF_MEMORY;
        }
    } else {
        EMSG("Invalid parameters for creating an object in secure storage");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_test_delete_persistent_object(
    uint32_t parameters_type,
    const TEE_Param parameters[1])
{
    TEE_Result result = 0;
    uint32_t expected_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, /* Name */
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if ((parameters_type == expected_types) &&
        (parameters != NULL) &&
        (parameters[0].memref.buffer != NULL) &&
        (parameters[0].memref.size > 1) &&
        (parameters[0].memref.size <= (uint32_t)DSEC_MAX_NAME_LENGTH)) {

        size_t name_size = (size_t)parameters[1].memref.size;
        char name[DSEC_MAX_NAME_LENGTH] = {0};

        const char* move_result = TEE_MemMove(name,
                                              parameters[0].memref.buffer,
                                              (uint32_t)name_size);

        if (move_result == name) {
            result = delete_persistent_object(name);
            if (result != TEE_SUCCESS) {
                EMSG("Could not delete the object from secure storage");
            }
        } else {
            EMSG("Name was not moved");
            result = TEE_ERROR_OUT_OF_MEMORY;
        }
    } else {
        EMSG("Invalid parameters for deleting an object in secure storage");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
#endif /* DSEC_TEST */
