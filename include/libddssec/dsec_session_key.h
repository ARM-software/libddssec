/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_session_key.h
 * Source code for handling Session Key.
 */

#ifndef DSEC_SESSION_KEY_H
#define DSEC_SESSION_KEY_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*! Maximum size of the session key. */
#define DSEC_MAX_SESSION_KEY_SIZE (32U)

/*!
 * \defgroup GroupSessionKey Session Key
 * \{
 */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * \brief Create a session key and return the buffer
 *
 * \param[out] session_key Output buffer that the key will be written to.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param km_handle_id Valid Key Material Handle ID.
 * \param session_id Session ID used for generation of the session key.
 * \param receiver_specific Receiver specific flag to indicate which session
 *     key to generate.
 *
 * \retval ::DSEC_SUCCESS Session key has been generated.
 * \return TEE_Result from the function DSEC_TA_CMD_SESSION_KEY_CREATE_AND_GET
 *     invoked in the TA converted to a DSEC_E_
 */
int32_t dsec_session_key_create_and_get(uint8_t* session_key,
                                        const struct dsec_instance* instance,
                                        int32_t km_handle_id,
                                        uint32_t session_id,
                                        bool receiver_specific);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_SESSION_KEY_H */
