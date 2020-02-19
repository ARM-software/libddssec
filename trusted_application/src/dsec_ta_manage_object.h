
/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DSEC_TA_MANAGE_OBJECT_H
#define DSEC_TA_MANAGE_OBJECT_H

#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <stdint.h>

/*!
 * \addtogroup GroupTA Trusted Application
 *
 * \brief Object management internal API.
 * \{
 */

/*! Maximum number of bytes for temporary internal storage */
#define DSEC_OBJECT_DATA_MAX_SIZE ((size_t)(2<<16))
/*! Maximum length of an object's name, including \0 */
#define DSEC_MAX_NAME_LENGTH (TEE_OBJECT_ID_MAX_LEN)

/*!
 * \brief Unload the object memory.
 *
 * \details Uses memset to set all of the object memory to zero and resets the
 *     metadata.
 */
void dsec_ta_unload_object_memory(void);

/*!
 * \brief Load a builtin object to the object memory.
 *
 * \details Find a builtin object by name and copy it to a temporary buffer.
 *     If an object has been loaded already, it must be unloaded by clearing
 *     the object memory.
 *
 * \param[out] buffer Pointer which is set to point to a pointer to a buffer of
 *     the loaded data.
 *
 * \param[in] size Pointer which is set to point to the size of the loaded
 *     data.
 *
 * \retval ::TEE_SUCCESS Success.
 * \retval ::TEE_ERROR_ITEM_NOT_FOUND Failed to find a matching object by name.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY There is already an object loaded.
 * \retval ::TEE_ERROR_BAD_PARAMETERS The pointer to object to be loaded is
 *     NULL.
 */
TEE_Result dsec_ta_load_builtin(void** buffer,
                                size_t* size,
                                const char name[DSEC_MAX_NAME_LENGTH]);

/*!
 * \brief Load an object to the object memory from the secure storage.
 *
 * \details Find a builtin object by name and copy it to a temporary buffer.
 *     If an object has been loaded already, it must be unloaded by clearing
 *     the object memory.
 *
 * \param[out] buffer Pointer which is set to point to a pointer to a buffer of
 *     the loaded data.
 *
 * \param[in] size Pointer which is set to point to the size of the loaded
 *     data.
 *
 * \param[in] name Array of the name of the object in secure storage. The name
 *     must be shorter than DSEC_MAX_NAME_LENGTH, including the \0.
 * \retval ::TEE_SUCCESS Success.
 * \retval ::TEE_ERROR_ITEM_NOT_FOUND Failed to find a matching object by name.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY There is already an object loaded.
 * \retval ::TEE_ERROR_BAD_PARAMETERS The pointer to object to be loaded is
 *     NULL.
 */
TEE_Result dsec_ta_load_storage(void** buffer,
                                size_t* size,
                                const char name[DSEC_MAX_NAME_LENGTH]);

/*!
 * \brief Create an object in the secure, persistent storage.
 *
 * \details Creates an object in the secure storage using a given name and
 *     buffer. This file will persist in other instances of the program.
 *
 * \param[in] name Array of the name of the object in secure storage.
 *
 * \param[in] name_size Size of the name.
 *
 * \param[in] buffer Array of the data of the object in secure storage.
 *
 * \param[in] size Size of the object in secure storage.
 *
 * \retval ::TEE_SUCCESS Success.
 * \retval ::TEE_ERROR_STORAGE_NOT_AVAILABLE The file can't be created and
 *     written to.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Bad parameters for creating an object.
 */
TEE_Result create_persistent_object(const char name[DSEC_MAX_NAME_LENGTH],
                                    void* buffer,
                                    size_t size);

/*!
 * \brief Delete an object from the secure, persistent storage.
 *
 * \details Deletes an object in the secure storage with a given name.
 *
 * \param[in] name Array of the name of the object in secure storage.
 *
 * \retval ::TEE_SUCCESS Success.
 * \retval ::TEE_ERROR_BAD_STATE The file can be opened but it can't be deleted.
 * \retval ::TEE_ERROR_ACCESS_DENIED The file can be opened but can't be
 *     written to.
 *
 * \retval ::TEE_ERROR_ITEM_NOT_FOUND The file can't be found.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Bad parameters for deleting an object.
 */
TEE_Result delete_persistent_object(const char name[DSEC_MAX_NAME_LENGTH]);

#if DSEC_TEST
/*!
 * \brief Invoke dsec_ta_load_builtin from the tests.
 *
 * \details Used for testing loading from the normal world.
 *
 * \param parameters_type The types of each of the parameters in parameters[1]
 *     as specified by the Global Platform TEE internal core API specification.
 *
 * \param[in] parameters[0].memref.buffer Pointer to a buffer containing the
 *     object ID name of the object.
 *
 * \retval ::TEE_SUCCESS Success.
 * \retval ::TEE_ERROR_ITEM_NOT_FOUND Failed to find a matching object by name.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY There is already an object loaded.
 * \retval ::TEE_ERROR_BAD_PARAMETERS The pointer to object to be loaded is
 *     NULL.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Wrong TEE_PARAM_TYPES (Testing error).
 * \retval ::TEE_ERROR_OUT_OF_MEMORY Couldn't copy name (Testing error).
 */
TEE_Result dsec_ta_test_load_object_builtin(uint32_t parameters_type,
                                            const TEE_Param parameters[1]);

/*!
 * \brief Invoke dsec_ta_load_storage from the tests.
 *
 * \details Used for testing loading from storage from the normal world.
 *
 * \param parameters_type The types of each of the parameters in parameters[1]
 *     as specified by the Global Platform TEE internal core API specification.
 *
 * \param[in] parameters[0].memref.buffer Pointer to a buffer containing the
 *     object ID name of the object.
 *
 * \param[in] parameters[0].memref.size The length of the object ID name of the
 *     object.
 *
 * \retval ::TEE_SUCCESS Success.
 * \retval ::TEE_ERROR_ITEM_NOT_FOUND Failed to find a matching object by name.
 * \retval ::TEE_ERROR_ACCESS_DENIED The file can be opened but can't be
 *     written to.
 *
 * \retval ::TEE_ERROR_OUT_OF_MEMORY There is already an object loaded.
 * \retval ::TEE_ERROR_BAD_PARAMETERS The pointer to object to be loaded is
 *     NULL.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Wrong TEE_PARAM_TYPES (Testing error).
 * \retval ::TEE_ERROR_OUT_OF_MEMORY Couldn't copy name (Testing error).
 */
TEE_Result dsec_ta_test_load_object_storage(uint32_t parameters_type,
                                            const TEE_Param parameters[1]);

/*!
 * \brief Invoke dsec_ta_unload_object_memory from the tests.
 *
 * \details Used for testing unloading from the normal world.
 *
 * \retval ::TEE_SUCCESS Success.
 * \retval ::TEE_ERROR_BAD_STATE The object_memory data or metadata was not
 *     reset.
 */
TEE_Result dsec_ta_test_unload_object(void);

/*!
 * \brief Invoke dsec_ta_test_create_persistent_object from the tests.
 *
 * \details Used for testing secure storage creation from the normal world.
 *
 * \param parameters_type The types of each of the parameters in parameters[1]
 *     as specified by the Global Platform TEE internal core API specification.
 *
 * \param[in] parameters[0].memref.buffer Pointer to a buffer containing the
 *     data of the object.
 *
 * \param[in] parameters[0].memref.size The size of the object.
 *
 * \param[in] parameters[1].memref.buffer Pointer to a buffer containing the
 *     name of the object.
 *
 * \param[in] parameters[1].memref.size The length of the name of the
 *     object.
 *
 * \retval ::TEE_SUCCESS Success.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY Couldn't copy over the name from the
 *     Normal World.
 * \retval ::TEE_ERROR_ACCESS_DENIED The file can be opened but can't be
 *     written to.
 * \retval ::TEE_ERROR_STORAGE_NOT_AVAILABLE The file can't be opened.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Bad parameters for creating an object.
 */
TEE_Result dsec_ta_test_create_persistent_object(
    uint32_t parameters_type,
    const TEE_Param parameters[2]);

/*!
 * \brief Invoke dsec_ta_test_delete_persistent_object from the tests.
 *
 * \details Used for testing secure storage deletion from the normal world.
 *
 * \param parameters_type The types of each of the parameters in parameters[1]
 *     as specified by the Global Platform TEE internal core API specification.
 *
 * \param[in] parameters[0].memref.buffer Pointer to a buffer containing the
 *     name of the object.
 *
 * \retval ::TEE_SUCCESS Success.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY Couldn't copy over the name from the
 *     Normal World.
 * \retval ::TEE_ERROR_BAD_STATE The file can be opened but it can't be deleted.
 * \retval ::TEE_ERROR_ACCESS_DENIED The file can be opened but can't be
 *     written to.
 *
 * \retval ::TEE_ERROR_ITEM_NOT_FOUND The file can't be found.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Bad parameters for deleting an object.
 */
TEE_Result dsec_ta_test_delete_persistent_object(
    uint32_t parameters_type,
    const TEE_Param parameters[1]);
#endif /* DSEC_TEST */
/*!
 * \}
 */

#endif /* DSEC_TA_MANAGE_OBJECT_H */
