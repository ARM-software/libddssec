/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_hh_dh.h
 * Source code for Diffie Hellman.
 */

#ifndef DSEC_HH_DH_H
#define DSEC_HH_DH_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * \addtogroup GroupHandshakeHandle
 *
 * Function for managing Diffie Hellman keys inside a Handshake Handle.
 * \{
 */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * \brief Generate a DH key pair
 *
 * \details Generate a Diffie Hellman key pair from a specific Handshake Handle.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param hh_id Handle ID of the Handshake Handle containing the DH key pair.
 *
 * \retval ::DSEC_SUCCESS
 * \return TEE_Result from the function DSEC_TA_CMD_HH_GENERATE invoked in the
 *     TA converted to a DSEC_E_
 */
int32_t dsec_hh_dh_generate(const struct dsec_instance* instance,
                            int32_t hh_id);

/*!
 * \brief Return a DH public key
 *
 * \details Return a Diffie Hellman public key from a specific Handshake Handle.
 *     The Handshake Handle must be initialized and contain a valid key.
 *
 * \param[out] buffer Valid memory pointer to a buffer that will contain the
 *     key.
 * \param[out] buffer_size Valid pointer containing the size of the buffer. This
 *     value will be updated with the actual number of bytes written to the
 *     buffer.
 * \param instance Initialized instance to access the Trusted Application
 * \param hh_id Handle ID of the Handshake Handle containing the DH key pair.
 *
 * \retval ::DSEC_SUCCESS
 * \return TEE_Result from the function DSEC_TA_CMD_HH_GET_PUBLIC invoked in the
 *     TA converted to a DSEC_E_
 */
int32_t dsec_hh_dh_get_public(void* buffer,
                              uint32_t* buffer_size,
                              const struct dsec_instance* instance,
                              int32_t hh_id);

/*!
 * \brief Unload a DH
 *
 * \details Unload a Diffie Hellman key of a specific Handshake Handle.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param hh_id Handle ID of the Handshake Handle containing the DH key pair.
 *
 * \retval ::DSEC_SUCCESS
 * \return TEE_Result from the function DSEC_TA_CMD_HH_DH_UNLOAD invoked in the
 *     TA converted to a DSEC_E_
 */
int32_t dsec_hh_dh_unload(const struct dsec_instance* instance, int32_t hh_id);

/*!
 * \brief Set a remote Diffie Hellman public key to a specific Handshake Handle.
 *
 * \details
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param hh_id Handle ID of the Handshake Handle.
 * \param buffer Buffer representing the public key.
 * \param buffer_size Size of the input buffer.
 *
 * \retval ::DSEC_SUCCESS Public key has been set.
 * \return TEE_Result from the function DSEC_TA_CMD_HH_SET_PUBLIC invoked in the
 *     TA converted to a DSEC_E_
 */
int32_t dsec_hh_dh_set_public(const struct dsec_instance* instance,
                              int32_t hh_id,
                              const void* buffer,
                              uint32_t buffer_size);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_HH_DH_H */
