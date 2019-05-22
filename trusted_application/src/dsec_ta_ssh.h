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
 * \brief Shared Key Handle (SKH) structure.
 *     Contains the derived key secret.
 */
struct shared_key_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! Size of the key. */
    size_t shared_key_size;
    /*! TEE_ structure representing the shared key. */
    TEE_ObjectHandle shared_key;
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
 *     different from success.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 * \param parameters[0].value.a Identifier of the Handshake Handle.
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
                                 TEE_Param parameters[1]);

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
 * \}
 */

#endif /* DSEC_TA_SSH_H */
