/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ssh.h
 * Source code for handling shared secrets.
 */

#ifndef DSEC_SSH_H
#define DSEC_SSH_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * \defgroup GroupSharedSecretHandle Function for Shared Secret Handle
 *     management.
 * \{
 */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * Structure containing all the information that can be extracted from a shared
 * secret handle.
 */
struct ssh_info_t {
    /*! Maximum number of handles that can be allocated. */
    uint32_t max_handle;
    /*! Current number of handles allocated. */
    uint32_t allocated_handle;
};

/*!
 * \brief Derive a shared secret
 *
 * \details Calls the Trusted Application to derive a shared secret from the
 *     information stored in the Handshake Handle specified.
 *
 * \param[out] ssh_id Handle ID of the shared secret.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param hh_id Handle ID of the Handshake Handle.
 *
 * \retval ::DSEC_SUCCESS Shared secret has been generated.
 * \return TEE_Result from the function DSEC_TA_CMD_SSH_DERIVE invoked in the TA
 *     converted to a DSEC_E_
 */
int32_t dsec_ssh_derive(int32_t* ssh_id,
                        const struct dsec_instance* instance,
                        int32_t hh_id);

/*!
 * \brief Get the data stored by a shared secret handle
 *
 * \details Calls the Trusted Application to get the data from a shared secret.
 *
 * \param[out] challenge1 Buffer where the challenge will be written.
 * \param[out] challenge1_size Pointer to the size of the buffer. This value is
 *     overwritten with the actual size of the output buffer.
 * \param[out] challenge2 Buffer where the challenge will be written.
 * \param[out] challenge2_size Pointer to the size of the buffer. This value is
 *     overwritten with the actual size of the output buffer.
 * \param[out] shared_key Buffer where the shared key will be written.
 * \param[out] shared_key_size Pointer to the size of the buffer. This value is
 *     overwritten with the actual size of the output buffer.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param ssh_id Handle ID of the shared secret.
 *
 * \retval ::DSEC_SUCCESS Data has been returned
 * \retval ::DSEC_E_PARAM Parameter types are not properly set or identifier
 *     specified leads to an invalid handle.
 * \retval ::DSEC_E_DATA At least one requested field is not initialized.
 * \retval ::DSEC_E_SHORT_BUFFER One of the buffer is not big enough.
 */
int32_t dsec_ssh_get_data(void* shared_key,
                          uint32_t* shared_key_size,
                          void* challenge1,
                          uint32_t* challenge1_size,
                          void* challenge2,
                          uint32_t* challenge2_size,
                          const struct dsec_instance* instance,
                          int32_t ssh_id);

/*!
 * \brief Delete a Shared Secret Handle
 *
 * \details Calls the Trusted Application to delete an allocated Shared Secret
 *     Handle ID.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param ssh_id Initialized Shared Secret Handle ID.
 *
 * \retval ::DSEC_SUCCESS Shared Secret Handle has been deleted.
 * \retval ::DSEC_E_PARAM Given parameters are invalid.
 */
int32_t dsec_ssh_delete(const struct dsec_instance* instance, int32_t ssh_id);

/*!
 * \brief Get information on the Trusted Application Shared Secret Handles
 *
 * \details Calls the Trusted Application to request information about the
 *     current status of the Shared Secret Handles: how many are allocated and
 *     how many can be allocated.
 *
 * \param [out] ssh_info pointer to a ssh_info_t structure where all the
 *      parameters are filled.
 *
 * \param instance Initialized instance to access the Trusted Application.
 *
 * \retval ::DSEC_SUCCESS Asked values are returned and valid.
 * \retval ::DSEC_E_PARAM Given parameters are invalid.
 */
int32_t dsec_ssh_get_info(struct ssh_info_t* ssh_info,
                          const struct dsec_instance* instance);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_SSH_H */
