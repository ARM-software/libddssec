/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_hh.h
 * Source code for handling the handshake process.
 */

#ifndef DSEC_HH_H
#define DSEC_HH_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * \defgroup GroupHandshakeHandle Function for Handshake Handle management
 * \{
 */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * \brief Create an Handshake Handle
 *
 * \details Calls the Trusted Application to request a new Handshake Handle ID.
 *
 * \param [out] hh_id ID of the Handshake Handle.
 * \param instance Initialized instance to access the Trusted Application
 *
 * \retval ::DSEC_SUCCESS Handshake Handle returned is valid and can be used.
 * \retval ::DSEC_E_PARAM Given parameters are invalid.
 * \retval ::DSEC_E_MEMORY The handle could not be allocated.
 */
int32_t dsec_hh_create(int32_t* hh_id, const struct dsec_instance* instance);

/*!
 * \brief Delete an Handshake Handle
 *
 * \details Calls the Trusted Application to delete an allocated Handshake
 *     Handle ID.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param hh_id Initialized Handshake Handle ID.
 *
 * \retval ::DSEC_SUCCESS Handshake Handle returned is valid and can be
 *     used.
 * \retval ::DSEC_E_PARAM Given parameters are invalid.
 */
int32_t dsec_hh_delete(const struct dsec_instance* instance,
                       int32_t hh_id);

/*!
 * \brief Get information on the Trusted Application Handshake Handles
 *
 * \details Calls the Trusted Application to request information about the
 *     current status of the Handshake Handles: how many are allocated and how
 *     many can be allocated.
 *
 * \param [out] max_handle Maximum number of Handshake Handles allowed by the TA
 * \param [out] allocated_handle Current number of allocated handles.
 *
 * \param instance Initialized instance to access the Trusted Application.
 *
 * \retval ::DSEC_SUCCESS Asked values are returned and valid.
 * \retval ::DSEC_E_PARAM Given parameters are invalid.
 */
int32_t dsec_hh_get_info(uint32_t* max_handle,
                         uint32_t* allocated_handle,
                         const struct dsec_instance* instance);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_HH_H */
