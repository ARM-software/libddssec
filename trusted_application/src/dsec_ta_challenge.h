/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ta_challenge.h
 * OP-TEE TA specific functions for generating challenges.
 */

#ifndef DSEC_TA_CHALLENGE_H
#define DSEC_TA_CHALLENGE_H

/*!
 * \addtogroup GroupTA Trusted Application
 * \{
 */

#include <tee_internal_api.h>

/*! Maximum size in byte of a challenge. */
#define DSEC_TA_CHALLENGE_MAX_DATA_SIZE 512

/*!
 * \brief Challenge Handle (CH)
 *     Contain a challenge generated or injected.
 */
struct challenge_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! Actual size of the challenge. */
    size_t data_size;
    /*! Byte array representing the challenge. */
    uint8_t data[DSEC_TA_CHALLENGE_MAX_DATA_SIZE];
};

/*!
 * \brief Generate the local challenge of a given Handshake Handle (HH)
 *
 * \details Given a the ID of a Handshake Handle, create a random array of bytes
 *     representing the challenge.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 * \param parameters[0].value.a Identifier of the Handshake Handle.
 * \param parameters[1].value.a Size in bytes of the challenge to be generated.
 * \param parameters[2].value.a Which challenge will be generated (1 or 2).
 *
 * \retval ::TEE_SUCCESS if the challenge is generated.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly
 *     set or if the identifier specified leads to an invalid handle.
 * \retval ::TEE_ERROR_NO_DATA One field of the Handshake Handle is not
 *     initialized.
 * \retval TEE_ERROR_SHORT_BUFFER if the number of byte requested is bigger than
 *     DSEC_TA_CHALLENGE_MAX_DATA_SIZE.
 */
TEE_Result dsec_ta_hh_challenge_generate(uint32_t parameters_type,
                                         const TEE_Param parameters[3]);

/*!
 * \brief Get the local challenge of a given Handshake Handle (HH)
 *
 * \details Given the ID of a Handshake Handle, return the local challenge.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].memref.buff Buffer containing the extracted
 *      challenge.
 * \param[out] parameters[0].memref.size Contains the incoming buffer size and
 *     is updated by the new output size.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \param parameters[1].value.a Identifier of the Handshake Handle.
 * \param parameters[2].value.a Which challenge will be generated (1 or 2).
 *
 * \retval ::TEE_SUCCESS Challenge is returned.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly
 *     set or if the identifier specified leads to an invalid handle.
 * \retval ::TEE_ERROR_NO_DATA The requested field of the Handshake Handle is
 *     not initialized.
 * \retval TEE_ERROR_SHORT_BUFFER Given buffer size is less than the
 *     size of the challenge.
 */
TEE_Result dsec_ta_hh_challenge_get(uint32_t parameters_type,
                                    TEE_Param parameters[3]);

/*!
 * \brief Unload the challenges of a given Handshake Handle (HH)
 *
 * \details Given the ID of a Handshake Handle, unload the challenge_handle_t
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
 * \retval ::TEE_SUCCESS Challenges are unloaded.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Pparameter types are not properly
 *     set or specified identifier leads to an invalid handle.
 * \retval ::TEE_ERROR_NO_DATA The field of the Handshake Handle is not
 *     initialized.
 */
TEE_Result dsec_ta_hh_challenge_unload(uint32_t parameters_type,
                                       const TEE_Param parameters[1]);

/*!
 * \brief Set the remote challenge of a given Handshake Handle (HH)
 *
 * \details Given a the ID of a Handshake Handle, set the remote challenge.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \param parameters[0].value.a Identifier of the Handshake Handle.
 * \param parameters[1].memref.buff Buffer containing the remote challenge.
 * \param parameters[1].memref.size Contains the buffer size.
 * \param parameters[2].value.a Which challenge will be set (1 or 2).
 *
 * \retval ::TEE_SUCCESS Challenge is returned.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly
 *     set or if the identifier specified leads to an invalid handle.
 * \retval ::TEE_ERROR_NO_DATA Request field in the Handshake Handle is not
 *     initialized.
 * \retval TEE_ERROR_SHORT_BUFFER Given buffer size is less than the size of the
 *     challenge.
 */
TEE_Result dsec_ta_hh_challenge_set(uint32_t parameters_type,
                                    const TEE_Param parameters[3]);

/*!
 * \}
 */

#endif /* DSEC_TA_CHALLENGE_H */
