/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_hh_challenge.h
 * Source code for challenge generation.
 */

#ifndef DSEC_HH_CHALLENGE_H
#define DSEC_HH_CHALLENGE_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * \defgroup GroupHandshakeHandle Function for Handshake Handle management
 *     specific to challenges.
 * \{
 */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * \brief Generate a challenge.
 *
 * \details Generate a random number of bytes to represent a challenge.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param hh_id Handle ID of the Handshake Handle.
 * \param size Number of random bytes to generate.
 * \param challenge_id Which challenge will be generated (1 or 2).
 *
 * \retval ::DSEC_SUCCESS Challenge is generated.
 * \retval ::DSEC_E_SHORT_BUFFER Cannot generate a challenge of that size.
 * \retval ::DSEC_E_DATA Invalid challenge id.
 * \retval ::DSEC_E_PARAM Invalid Handshake Handle ID.
 */
int32_t dsec_hh_challenge_generate(const struct dsec_instance* instance,
                                   int32_t hh_id,
                                   uint32_t size,
                                   uint8_t challenge_id);

/*!
 * \brief Return a challenge.
 *
 * \details Return the requested challenge as array.
 *
 * \param[out] buffer Array that will contain the challenge.
 * \param[out] buffer_size Size of incoming buffer, updated with the number of
 *     bytes written.
 * \param instance Initialized instance to access the Trusted Application
 * \param hh_id Handle ID of the Handshake Handle.
 * \param challenge_id Which challenge will be generated (1 or 2)
 *
 * \retval ::DSEC_SUCCESS Challenge is copied to input buffer.
 * \retval ::DSEC_E_SHORT_BUFFER Input buffer is too small.
 * \retval ::DSEC_E_DATA Invalid challenge id.
 * \retval ::DSEC_E_PARAM Invalid Handshake Handle ID.
 */
int32_t dsec_hh_challenge_get(void* buffer,
                              uint32_t* buffer_size,
                              const struct dsec_instance* instance,
                              int32_t hh_id,
                              uint8_t challenge_id);

/*!
 * \brief Unload challenges from a Handshake Handle.
 *
 * \details Unload all the challenges from a Handshake Handle.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param hh_id Handle ID of the Handshake Handle.
 *
 * \retval ::DSEC_SUCCESS Challenges are unloaded.
 * \retval ::DSEC_E_DATA Handshake Handle ID has no challenge loaded.
 * \retval ::DSEC_E_PARAM Invalid Handshake Handle ID.
 */
int32_t dsec_hh_challenge_unload(const struct dsec_instance* instance,
                                 int32_t hh_id);

/*!
 * \brief Set a remote challenge to a specific Handshake Handle.
 *
 * \details Given a buffer, set the challenge in the Handshake Handle.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param hh_id Handle ID of the Handshake Handle.
 * \param buffer Buffer containing the challenge.
 * \param buffer_size Size of the input buffer.
 * \param challenge_id Which challenge will be generated (1 or 2).
 *
 * \retval ::DSEC_SUCCESS Challenge has been set.
 * \return TEE_Result from the function DSEC_TA_CMD_HH_SET_PUBLIC invoked in the
 *     TA converted to a DSEC_E_
 */
int32_t dsec_hh_challenge_set(const struct dsec_instance* instance,
                              int32_t hh_id,
                              const void* buffer,
                              uint32_t buffer_size,
                              uint8_t challenge_id);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_HH_CHALLENGE_H */
