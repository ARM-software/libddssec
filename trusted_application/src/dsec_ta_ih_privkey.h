/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ta_ih_privkey.h
 * TA source code for handling the private keys.
 */

#ifndef DSEC_TA_IH_PRIVKEY_H
#define DSEC_TA_IH_PRIVKEY_H

/*!
 * \addtogroup GroupTA Trusted Application
 * \{
 */

#include <mbedtls/x509_crt.h>
#include <tee_api.h>
#include <stdint.h>
#include <stdbool.h>

/*!
 * \brief Private key structure.
 */
struct privkey_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! mbedTLS structure representing the private key of a node. */
    mbedtls_pk_context privkey;
};

/*!
 * \brief Load a private key from storage
 *
 * \details Given a string identifier representing the name of the private key,
 * load the private key into memory. If provided, apply the given password.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[0] Handle ID of the Identity Handle
 * \param parameters[1] Buffer containing the name of the certificate to be
 *     retrieved from disk.
 * \param parameters[2] Buffer containing the password to be applied to the
 *     private key.
 *
 * \retval ::TEE_SUCCESS Private key is loaded.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_ih_privkey_load(uint32_t parameters_type,
                                   const TEE_Param parameters[3]);

/*!
 * \brief Given a privkey_handle_t structure, clean the private key.
 *
 * \details Free the mbedTLS structure containing the private key and mark the
 *    private key handle as uninitialized.
 *
 * \param privkey_handle Pointer to a structure to be cleaned.
 *
 * \retval ::TEE_SUCCESS Structure is freed.
 * \retval ::TEE_ERROR_NO_DATA Structure was not initialized.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Structure pointer is NULL.
 */
TEE_Result dsec_ta_ih_privkey_free(struct privkey_handle_t* privkey_handle);

/*!
 * \brief Given an Identity Handle, clean the associated private key.
 *
 * \details Check if the handle is valid, clean the mbedTLS structure and
 * uninitialize the element
 *
 * \param parameters[0] Handle to be unloaded.
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 *
 * \retval ::TEE_SUCCESS Handle is unloaded.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set or
 *     handle was not initialized/out-of-bounds.
 */
TEE_Result dsec_ta_ih_privkey_unload(uint32_t parameters_type,
                                     const TEE_Param parameters[1]);

/*!
 * \brief Sign a message using a Private Key from an Identity Handle.
 *
 * \details Retrieve the Private Key of the Identity Handle and sign the
 *     buffer. Return the signature to the Client Application.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].memref.buffer Output buffer containing the
 *     signature.
 * \param[out] parameters[0].memref.size Size of the incoming output buffer.
 *     This will be updated with the actual number of bytes written to the
 *     buffer.
 *
 * \param parameters_type The types of each of the parameters in parameters[3]
 *     as described above.
 * \param parameters[1] Identity Handle ID of the Identity Handle.
 * \param parameters[2].memref.buffer Input message to sign.
 * \param parameters[2].memref.size Input buffer size.
 *
 * \retval ::TEE_SUCCESS Signature is written to the input buffer.
 * \retval ::TEE_ERROR_NO_DATA Private key is not initialized.
 * \retval ::TEE_ERROR_BAD_FORMAT Private key cannot be parsed.
 * \retval ::TEE_ERROR_SECURITY Signature cannot be generated.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter type are not properly set.
 */
TEE_Result dsec_ta_ih_privkey_sign(uint32_t parameters_type,
                                   TEE_Param parameters[3]);

/*!
 * \}
 */

#endif /* DSEC_TA_IH_PRIVKEY_H */
