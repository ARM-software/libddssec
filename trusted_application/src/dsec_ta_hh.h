/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ta_hh.h
 * OP-TEE TA specific for storing handles used for handshakes
 */

#ifndef DSEC_TA_HANDSHAKE_HANDLE_H
#define DSEC_TA_HANDSHAKE_HANDLE_H

/*!
 * \addtogroup GroupTA Trusted Application
 * \{
 */

#include <dsec_ta_dh.h>
#include <tee_api.h>
#include <stdint.h>
#include <stdbool.h>

/*!
 * \brief Maximum number of Handshake Handles that can be loaded concurrently
 */
#define DSEC_TA_MAX_HANDSHAKE_HANDLE (4U)

/*
 * Extra care is taken here to make sure the maximum size of the array storing
 * the handles cannot exceed INT32_MAX. This is because OPTEE-OS parameters are
 * uint32_t and the index of a handle is an int32_t. When the cast occurres, if
 * the index overflows, it will make the handle ID invalid.
 */
#if (DSEC_TA_MAX_HANDSHAKE_HANDLE > INT32_MAX)
#error "DSEC_TA_MAX_HANDSHAKE_HANDLE cannot be more than INT32_MAX"
#endif

/*!
 * \brief Handshake Handle (HH) structure.
 */
struct handshake_handle_t {
    /*! Initialized field set to true if the structure has been set. */
    bool initialized;
    /*! Diffie Hellman key pair structure. */
    struct dh_pair_handle_t dh_pair_handle;
    /* Diffie Hellman public key structure */
    struct dh_public_handle_t dh_public_handle;
};

/*!
 * \brief Create a Handshake Handle
 *
 * \details Allocate one element to store a Handshake Handle and return the
 *     corresponding ID.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_OUTPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param [out] parameters[0].value.a Handle ID of the Handshake Handle.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \retval ::TEE_SUCCESS Handshake Handle is allocated and its ID is returned.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY No more space to allocate a new handle.
 */
TEE_Result dsec_ta_hh_create(uint32_t parameters_type, TEE_Param parameters[1]);

/*!
 * \brief Delete a Handshake Handle
 *
 * \details Delete the corresponding Handshake Handle from the ID specified.
 *     If the Handshake Handle contains any initialized structures, they are
 *     cleared.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters[0].value.a Handle ID of the Handshake Handle.
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \retval ::TEE_SUCCESS Handshake Handle has been removed.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_hh_delete(uint32_t parameters_type, TEE_Param parameters[1]);

/*!
 * \brief Return a Handshake Handle structure
 *
 * \details Look for the given Handshake Handle ID and return its associated
 *     structure.
 *
 * \param hh_id Handle ID of the Handshake Handle.
 *
 * \retval ::struct handshake_handle_t* on success.
 * \retval ::NULL Handshake Handle could not be retrieved.
 */
struct handshake_handle_t* dsec_ta_get_handshake_handle(int32_t hh_id);

/*!
 * \brief Get information about the Handshake Handle usage
 *
 * \details Return the maximum number of handles that can be allocated and the
 *     number of handles that are allocated so far.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_OUTPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param [out] parameters[0].value.a Maximum number of handles that can be
 *     allocated.
 * \param [out] parameters[0].value.b Current number of allocated handles.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \retval ::TEE_SUCCESS Numbers are correctly retrieved and returned.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_hh_get_info(uint32_t parameters_type,
                               TEE_Param parameters[1]);

/*!
 * \}
 */

#endif /* DSEC_TA_HANDSHAKE_HANDLE_H */
