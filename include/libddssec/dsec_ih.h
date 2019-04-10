/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ih.h
 * Source code for handling the identity of a specific node.
 */

#ifndef DSEC_IH_H
#define DSEC_IH_H

/*!
 * \defgroup GroupIdentityHandle Identity Handle management
 * \{
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * \brief Create an Identity Handle
 *
 * \details Calls the Trusted Application to request a new Identity Handle ID.
 *
 * \param [out] ih_id ID of the Identity Handle.
 * \param instance Initialized instance to access the Trusted Application.
 *
 * \retval ::DSEC_SUCCESS Identity Handle returned is valid and can be used.
 * \retval ::DSEC_E_PARAM Given parameters are invalid.
 * \retval ::DSEC_E_MEMORY The handle could not be allocated.
 */
int32_t dsec_ih_create(int32_t* ih_id, const struct dsec_instance* instance);

/*!
 * \brief Delete an Identity Handle
 *
 * \details Calls the Trusted Application to delete an allocated Identity Handle
 *     ID.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param ih_id ID to an initialized Identity Handle.
 *
 * \retval ::DSEC_SUCCESS Identity Handle has been removed.
 * \retval ::DSEC_E_PARAM Given parameters are invalid.
 */
int32_t dsec_ih_delete(const struct dsec_instance* instance, int32_t ih_id);

/*!
 * \brief Get information on the Trusted Application Identity Handles
 *
 * \details Calls the Trusted Application to request information about the
 *     current status of the Identity Handles: How many are allocated and how
 *     many can be allocated.
 *
 * \param [out] max_handle Maximum number of Identity Handles allowed by the TA
 * \param [out] allocated_handle Current number of allocated handles.
 *
 * \param instance Initialized instance to access the Trusted Application.
 *
 * \retval ::DSEC_SUCCESS Asked values are returned and valid.
 * \retval ::DSEC_E_PARAM Given parameters are invalid.
 */
int32_t dsec_ih_get_info(uint32_t* max_handle,
                         uint32_t* allocated_handle,
                         const struct dsec_instance* instance);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_IH_H */
