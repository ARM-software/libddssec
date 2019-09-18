/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DSEC_TA_SESSION_KEY_H
#define DSEC_TA_SESSION_KEY_H

#include <tee_api.h>
#include <stdint.h>
#include <stdbool.h>

/*! Maximum size of the session key. */
#define DSEC_TA_MAX_SESSION_KEY_SIZE (32U)

/*!
 * \brief Maximum number of Session Key Handles that can be loaded concurrently.
 */
#define DSEC_TA_MAX_SESSION_KEY_HANDLE (64U)

/*
 * Extra care is taken here to make sure the maximum size of the array storing
 * the handles cannot exceed INT32_MAX. This is because OPTEE-OS parameters are
 * uint32_t and the index of a handle is an int32_t. When the cast occurs, if
 * the index overflows, it will make the handle ID invalid.
 */
#if (DSEC_TA_MAX_SESSION_KEY_HANDLE > INT32_MAX)
#error "DSEC_TA_MAX_SESSION_KEY_HANDLE cannot be more than INT32_MAX"
#endif

#define DSEC_TA_MAX_SESSION_KEY_SIZE (32U)

/*!
 * \brief Session Key Handle structure.
 */
struct session_key_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! Array containing the data. */
    uint8_t data[DSEC_TA_MAX_SESSION_KEY_SIZE];
};

/*!
 * \brief Create and return a session key.
 *
 * \details Use the parameters given to retrieve the key material and compute
 *     the corresponding session key.
 *     The TEE_Param expected are:
 *         - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *         - TEE_PARAM_TYPE_VALUE_INPUT
 *         - TEE_PARAM_TYPE_VALUE_INPUT
 *         - TEE_PARAM_TYPE_NONE
 *
 * \param[out] parameters[0].memref.buffer Output buffer.
 * \param[out] parameters[0].memref.size Output buffer size updated with the
 *     number of bytes written.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[1].value.a Valid key material handle ID.
 * \param parameters[2].value.a Session ID used for generation of the key.
 * \param parameters[2].value.b Receiver specific flag to indicate which session
 *     key to generate.
 *
 * \retval ::TEE_SUCCESS the session key has eben generated and returned.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_session_key_create_and_get(uint32_t parameters_type,
                                              TEE_Param parameters[3]);

TEE_Result dsec_ta_session_key_create(uint32_t parameters_type,
                                      TEE_Param parameters[3]);

TEE_Result dsec_ta_session_key_delete(uint32_t parameters_type,
                                      const TEE_Param parameters[1]);

TEE_Result dsec_ta_session_key_encrypt(uint32_t parameters_type,
                                       TEE_Param parameters[4]);

TEE_Result dsec_ta_session_key_decrypt(uint32_t parameters_type,
                                       TEE_Param parameters[4]);

#endif /* DSEC_TA_SESSION_KEY_H */
