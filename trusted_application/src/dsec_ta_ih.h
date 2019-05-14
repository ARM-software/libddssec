/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ta_ih.h
 * TA source code for handling the identity of a specific node.
 */

#ifndef DSEC_TA_IH_H
#define DSEC_TA_IH_H

/*!
 * \addtogroup GroupTA Trusted Application
 *
 * Function for handling Identity Handles.
 * \{
 */

#include <dsec_ta_ih_ca.h>
#include <dsec_ta_ih_cert.h>
#include <tee_api.h>
#include <stdint.h>
#include <stdbool.h>

/*!
 * \brief Maximum number of Identity Handles that can be loaded concurrently.
 */
#define DSEC_TA_MAX_IDENTITY_HANDLE (4U)

/*
 * Extra care is taken here to make sure the maximum size of the array storing
 * the handles cannot exceed INT32_MAX. This is because OPTEE-OS parameters are
 * uint32_t and the index of a handle is an int32_t. When the cast occurres, if
 * the index overflows, it will make the handle ID invalid.
 */
#if (DSEC_TA_MAX_IDENTITY_HANDLE > INT32_MAX)
#error "DSEC_TA_MAX_IDENTITY_HANDLE cannot be more than INT32_MAX"
#endif

/*!
 * \brief Identity Handle (IH) structure.
 */
struct identity_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! Certificate Authority structure. */
    struct ca_handle_t ca_handle;
    /*! Certificate of identity structure. */
    struct cert_handle_t cert_handle;
};

/*!
 * \brief Create an Identity Handle
 *
 * \details Search for an initialized element and allocate one for an Identity
 *     Handle in the array and return the corresponding ID.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_OUTPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param [out] parameters[0].value.a Handle ID of the Identity Handle.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \retval ::TEE_SUCCESS Identity Handle is created and its ID returned.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter are not properly set.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY If there is no more space in the array to
 *     store a new handle.
 */
TEE_Result dsec_ta_ih_create(uint32_t parameters_type, TEE_Param parameters[1]);

/*!
 * \brief Delete an Identity Handle
 *
 * \details Delete the corresponding Identity Handle in the array from the ID
 *     specified. This function clears all the initialized structure it may
 *     contain.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 * \param parameters[0].value.a Handle ID of the Identity Handle.
 *
 * \retval ::TEE_SUCCESS Identity Handle has been removed from the array.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter are not properly set.
 */
TEE_Result dsec_ta_ih_delete(uint32_t parameters_type,
                             const TEE_Param parameters[1]);

/*!
 * \brief Return an Identity Handle structure
 *
 * \details Look for the given Identity Handle ID and return its associated
 *     structure.
 *
 * \param ih_id Handle ID of the Identity Handle.
 *
 * \retval ::struct identity_handle_t* on success.
 * \retval ::NULL Handle could not be retrieved.
 */
struct identity_handle_t* dsec_ta_get_identity_handle(int32_t ih_id);

/*!
 * \brief Get information about the Identity Handle usage
 *
 * \details Return the maximum size of the array containing the handle and the
 *     number of handles that are allocated.
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
 * \retval ::TEE_SUCCESS Numbers are correctly retrieved.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter are not properly set.
 */
TEE_Result dsec_ta_ih_get_info(uint32_t parameters_type,
                               TEE_Param parameters[1]);

/*!
 * \}
 */

#endif /* DSEC_TA_IH_H */
