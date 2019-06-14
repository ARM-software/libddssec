/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ta_ssh.h
 * OP-TEE TA specific for Shared Secret Handle operations.
 */

#ifndef DSEC_TA_SSH_H
#define DSEC_TA_SSH_H

/*!
 * \addtogroup GroupTA Trusted Application
 * \{
 */

#include <dsec_ta_challenge.h>
#include <tee_internal_api.h>
#include <stdbool.h>
#include <stddef.h>

/*!
 * \brief Maximum number of Shared Secret Handles that can be loaded
 *     concurrently.
 */
#define DSEC_TA_MAX_SHARED_SECRET_HANDLE (4U)

/*
 * Extra care is taken here to make sure the maximum size of the array storing
 * the handles cannot exceed INT32_MAX. This is because OPTEE-OS parameters are
 * uint32_t and the index of a handle is an int32_t. When the cast occurres, if
 * the index overflows, it will make the handle ID invalid.
 */
#if (DSEC_TA_MAX_SHARED_SECRET_HANDLE > INT32_MAX)
#error "DSEC_TA_MAX_SHARED_SECRET_HANDLE cannot be more than INT32_MAX"
#endif

/*!
 * \brief Maximum number of bytes for the shared secret.
 */
#define DSEC_TA_MAX_SHARED_KEY_SIZE (1024U)

/*!
 * \brief Maximum number of bytes for the hash of the shared secret.
 */
#define DSEC_TA_MAX_HASH_SHARED_KEY_SIZE (32U)

/*!
 * \brief Shared Key Handle (SKH) structure.
 *     Contains the derived key secret.
 */
struct shared_key_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! Size of the hashed key. */
    size_t data_size;
    /*! TEE_ structure representing the hashed shared key. */
    uint8_t data[DSEC_TA_MAX_HASH_SHARED_KEY_SIZE];
};

/*!
 * \brief Shared Secret Handle (SSH) structure.
 *     Contains the derived key secret.
 */
struct shared_secret_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! Shared Key Handle structure. */
    struct shared_key_handle_t shared_key_handle;
    /*! Challenge Handle. */
    struct challenge_handle_t challenge1_handle;
    /*! Challenge Handle. */
    struct challenge_handle_t challenge2_handle;
};

/*!
 * \brief Derive the shared key from the given Handshake Handle (HH)
 *
 * \details Given a the ID of a Handshake Handle, retrieve the structure and
 *     derive the shared key from the Public/Private keys of the local identity
 *     and the Public key from the remote identity stored in the Handshake
 *     Handle. If there is a field non initialialized, this call return a value
 *     different from success. This function returns the identifier of the
 *     Shared Secret Handle.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_OUTPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters[0].value.a Identifier of the Shared Secret Handle.
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 * \param parameters[1].value.a Identifier of the Handshake Handle.
 *
 * \retval ::TEE_SUCCESS The key has been derived.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly
 *     set or specified identifier leads to an invalid handle.
 * \retval ::TEE_ERROR_NO_DATA One field of the Handshake Handle is not
 *     initialized.
 * \retval TEE_Result from TEE_AllocateOperation, TEE_SetOperationKey,
 *     TEE_AllocateTransientObject, TEE_GetObjectBufferAttribute functions which
 *     indicates an error during the derivation of the key.
 */
TEE_Result dsec_ta_hh_ssh_derive(uint32_t parameters_type,
                                 TEE_Param parameters[2]);

/*!
 * \brief Free a shared_secret_handle structure (SSH)
 *
 * \details Given a structure, free all initialized fields.
 *
 * \param shared_secret_handle pointer to the structure to be freed
 *
 * \retval ::TEE_SUCCESS if the structure was freed properly.
 * \retval ::TEE_ERROR_NO_DATA if the given shared_secret_handle is NULL or
 *     was not initialized.
 */
TEE_Result dsec_ta_ssh_free(
    struct shared_secret_handle_t* shared_secret_handle);

/*!
 * \brief Create a shared_secret_handle structure (SSH) and return its index.
 *
 * \details Allocate the handle and return its identifier.
 *
 * \param[out] index Pointer to an integer that will contain the index. The
 *     index returned will be greater or equal than 0 on success.
 *
 * \retval ::TEE_SUCCESS if the index returned is valid.
 * \retval ::TEE_ERROR_BAD_PARAMETERS if the index pointer is NULL.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY if there are no more valid handle in the
 *     array.
 */
TEE_Result dsec_ta_ssh_create(int32_t* index);

/*!
 * \brief Given an index, return a pointer to shared_secret_handle_t (SSH).
 *
 * \details Check the incoming index and return the associated handle if it
 *     is initialized.
 *
 * \param index Index of the handle.
 *
 * \return Pointer to shared_secret_handle_t
 * \retval ::NULL if the given index does not lead to a valid handle.
 */
struct shared_secret_handle_t* dsec_ta_ssh_get(int32_t index);

/*!
 * \brief Get information about the current status of the Shared Secret Handle.
 *
 * \details Return the the number of handles currently allocated and the maximum
 *     number of handles that can be allocated.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_OUTPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \param[out] parameters[0].value.a Maximum number of handles.
 * \param[out] parameters[0].value.b Current number of allocated handles.
 *
 * \retval ::TEE_SUCCESS
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_ssh_get_info(uint32_t parameters_type,
                                TEE_Param parameters[1]);

/*!
 * \brief Unload the given Shared Secret Handle (SHH)
 *
 * \details Given the ID of a Shared Secret Handle, unload the structure.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 * \param parameters[0].value.a Identifier of the Shared Secret Handle.
 *
 * \retval ::TEE_SUCCESS Handle is unloaded.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set or
 *     identifier specified leads to an invalid handle.
 * \retval ::TEE_ERROR_NO_DATA Structure has uninitialized fields.
 */
TEE_Result dsec_ta_ssh_unload(uint32_t parameters_type,
                              const TEE_Param parameters[1]);

/*!
 * \brief [UNSAFE] Return all the data fields of a Shared Secret Handle (SHH)
 *
 * \details Extract the fields of the shared secret handle outside the TA.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *
 * \param[out] parameters[0].memref.buffer Shared Secret data.
 * \param[out] parameters[0].memref.size Shared Secret size.
 * \param[out] parameters[1].memref.buffer Challenge1 data.
 * \param[out] parameters[1].memref.size Challenge1 size.
 * \param[out] parameters[2].memref.buffer Challenge2 data.
 * \param[out] parameters[2].memref.size Challenge2 size.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 * \param parameters[3].value.a Identifier of the Shared Secret Handle.
 *
 * \retval ::TEE_SUCCESS Attributes of the structures are returned.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set or
 *     identifier specified leads to an invalid handle.
 * \retval ::TEE_ERROR_NO_DATA One field of a structure is not initialized.
 * \retval ::TEE_ERROR_SHORT_BUFFER One of the buffer is not big enough.
 * \retval TEE_Result from TEE_GetObjectBufferAttribute
 */
TEE_Result dsec_ta_ssh_get_data(uint32_t parameters_type,
                                TEE_Param parameters[4]);
/*!
 * \}
 */

#endif /* DSEC_TA_SSH_H */
