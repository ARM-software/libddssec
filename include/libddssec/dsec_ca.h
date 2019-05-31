/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * \file
 * \brief \copybrief GroupClientApplication
 */

#ifndef DSEC_CA_H
#define DSEC_CA_H

/*!
 * \defgroup GroupClientApplication Client Application
 * \{
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <tee_client_api.h>
#include <stdbool.h>
#include <stdint.h>

/*!
 * \brief Special type to combine a TEE Client context and session for
 *     ease-of-use.
 */
struct dsec_instance {
    /*! Context structure to a TEE-OS. */
    TEEC_Context* context;
    /*! Session structure to a Trusted Application. */
    TEEC_Session* session;
    /*! Indicate if the instance has been open. This should not be modified
     *     directly. */
    bool open;
};

/*!
 * \brief Create and return a new instance.
 *
 * \details Assign the given pointers to the structure and return the new
 *    created instance.
 *
 * \param session Pointer to a session.
 * \param context Pointer to a context.
 *
 * \return struct dsec_instance returned structure with the pointers assigned.
 */
struct dsec_instance dsec_ca_instance_create(TEEC_Session* session,
                                             TEEC_Context* context);

/*!
* \brief Open an instance.
*
* \details Open the instance if it has not already been opened, then sets the
*     meta-data to say the instance is open.
*
* \param instance Pointer to a dsec instance created.
*
* \retval ::DSEC_SUCCESS the session was successfully open.
* \retval ::DSEC_E_INIT the context or session could not be initialized.
*/
int32_t dsec_ca_instance_open(struct dsec_instance* instance);

/*!
* \brief Close an instance.
*
* \details Close the instance if it is open, then sets the meta-data to say the
*     instance is closed.
*
* \param instance Pointer to a dsec instance opened.
*
* \retval ::DSEC_SUCCESS The session was successfully closed.
* \retval ::DSEC_E_PARAM Instance is NULL or has a context or session NULL.
* \retval ::DSEC_E_INIT Instance does not have the correct status.
*/
int32_t dsec_ca_instance_close(struct dsec_instance* instance);

/*!
* \brief Close an instance.
*
* \details Check the parameters for safe values before calling
*      TEEC_InvokeCommand to invoke a function within the TA.
*
* \param instance Pointer to a dsec_instance opened.
* \param command_id Value from the DSEC_TA_CMD_ enum from dsec_ta.h
* \param operation Pointer to a dsec instance opened.
* \param origin Pointer to uint32_t storing the return origin value. This field
*     may be NULL.
*
* \retval TEEC_SUCCESS The command has been successful.
* \return TEEC_ value returned by TEEC_InvokeCommand
*/
TEEC_Result dsec_ca_invoke(const struct dsec_instance* instance,
                           uint32_t command_id,
                           TEEC_Operation* operation,
                           uint32_t* origin);

/*!
* \brief Convert a TEEC_Result to a DSEC_ code.
*
* \details Convert the incoming code to a DSEC_ code in dsec_errno.h
*
* \param teec_result error code returned by a TEE.
*
* \retval ::DSEC_SUCCESS the session was successfully open.
* \return DSEC_E_ in the file dsec_errno.h
*/
int32_t dsec_ca_convert_teec_result(TEEC_Result teec_result);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*!
 * \}
 */

#endif /* DSEC_CA_H */
