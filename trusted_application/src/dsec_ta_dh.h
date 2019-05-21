/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ta_dh.h
 * OP-TEE TA specific Diffie Hellman (DH) key operations.
 */

#ifndef DSEC_TA_DH_H
#define DSEC_TA_DH_H

/*!
 * \addtogroup GroupTA Trusted Application
 *
 * Function for Diffie Hellman operations.
 * \{
 */

#include <tee_internal_api.h>

/*! Maximum number of bits for the Diffie Hellman Key */
#define DSEC_TA_DH_MAX_KEY_BITS 2048
/*! Maximum number of bytes for the Diffie Hellman Key */
#define DSEC_TA_DH_MAX_KEY_BYTES (DSEC_TA_DH_MAX_KEY_BITS/8)

/*!
 * \brief Diffie Hellman key pair structure.
 */
struct dh_pair_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! Structure containing the public and private key. */
    TEE_ObjectHandle key_pair;
};

/*!
 * \brief Diffie Hellman public key structure.
 */
struct dh_public_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! Array containing the public key. */
    uint8_t key[DSEC_TA_DH_MAX_KEY_BYTES];
    /*! Size of the public key stored. */
    size_t key_size;
};

/*!
 * \brief Generate a Diffie Hellman key pair.
 *
 * \details Given a Hanshake Handle ID, fills the structure containing the
 *     Diffie Hellman key pair.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 * \param parameters[0].value.a Handle ID of the Handshake Handle.
 *
 * \retval ::TEE_SUCCESS DH key pair generated.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter are not properly set.
 * \retval ::TEE_ERROR_NO_DATA The key pair is already initialized.
 */
TEE_Result dsec_ta_hh_dh_generate_keys(uint32_t parameters_type,
                                       TEE_Param parameters[1]);

/*!
 * \brief Return public part of generated Diffie Hellman key pair.
 *
 * \details Given a Handshake Handle ID, return the associated public key.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].memref.buffer Output buffer.
 * \param[out] parameters[0].memref.size Size of the incoming output buffer.
 *     This will be updated with the actual number of bytes written to the
 *     buffer.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 * \param parameters[1].value.a Handle ID of the Handshake Handle.
 *
 * \retval ::TEE_SUCCESS Public key returned to the buffer.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter are not properly set.
 * \retval ::TEE_ERROR_SHORT_BUFFER Given output buffer is too small.
 */
TEE_Result dsec_ta_hh_dh_get_public(uint32_t parameters_type,
                                    TEE_Param parameters[2]);

/*!
 * \brief Free Diffie Hellman handle
 *
 * \details Delete the corresponding Diffie Hellman data from the key pair
 *     structure.
 *
 * \param key_pair Structure to be freed.
 *
 * \retval ::TEE_SUCCESS Handle has been freed.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Given argument is NULL.
 */
TEE_Result dsec_ta_hh_dh_free_keypair(struct dh_pair_handle_t* key_pair);

/*!
 * \brief Delete a Diffie Hellman Handle
 *
 * \details Delete the corresponding Diffie Hellman data from the specified
 *     Handshake Handle ID.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters[0].value.a Handshake Handle ID of the Handshake Handle.
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \retval ::TEE_SUCCESS All associated Diffie Hellman are unloaded from the
 *     handle.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter are not properly set.
 */
TEE_Result dsec_ta_hh_dh_unload(uint32_t parameters_type,
                                TEE_Param parameters[1]);

/*!
 * \brief Set public key of a Handshake Handle.
 *
 * \details Given a Handshake Handle ID, copy the given buffer to the public key
 *     structure.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 * \param parameters[0].value.a Handle ID of the Handshake Handle.
 * \param parameters[1].memref.buffer Input buffer.
 * \param parameters[1].memref.size Size of the incoming buffer.
 *
 * \retval ::TEE_SUCCESS Public key has been copied to the structure.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameters are not properly set.
 * \retval ::TEE_ERROR_SHORT_BUFFER Input buffer is too big to be stored.
 */
TEE_Result dsec_ta_hh_dh_set_public(uint32_t parameters_type,
                                    TEE_Param parameters[2]);

#endif /* DSEC_TA_DH_H */
