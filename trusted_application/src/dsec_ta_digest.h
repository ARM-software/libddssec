/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ta_digest.h
 * TA source code for performing a SHA256 digest.
 */

#ifndef DSEC_TA_DIGEST_H
#define DSEC_TA_DIGEST_H

/*! Size of a completed SHA256 digest */
#define DSEC_TA_SHA256_SIZE (32U)

/*!
 * \addtogroup GroupTA Trusted Application
 *
 * Function for performing digests.
 * \{
 */

#include <tee_api.h>

/*!
 * \brief Perform a SHA256 digest
 *
 * \details Take an input buffer and return the SHA256 digest of the buffer.
 *
 * \param [out] output SHA256 hash of the input buffer.
 * \param input Input buffer which will be hashed.
 * \param input_size Size of the input buffer.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \retval ::DSEC_SUCCESS Input buffer has been hashed and returned.
 * \retval ::DSEC_E_DATA Could not get digest type information.
 * \retval ::DSEC_E_DATA Could not perform digest.
 *
 */
int32_t dsec_ta_digest_sha256(uint8_t* output,
                              const uint8_t* input,
                              size_t input_size);

#if DSEC_TEST
/*!
 * \brief Perform a SHA256 digest on a buffer from the Normal World and return
 * it to the Normal World.
 *
 * \details Take an input buffer and return the SHA256 digest of the buffer.
 *     The expected TEE_Params are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param [out] parameters[0].memref.buf SHA256 hash of the input buffer.
 * \param [out] parameters[1].memref.buf Input buffer which will be hashed.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \retval ::TEE_SUCCESS Input buffer has been hashed and returned.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameters are not properly set.
 * \retval ::TEE_ERROR_BAD_STATE Could not perform digest.
 *
 */
TEE_Result dsec_ta_test_sha256(uint32_t parameters_type,
                               TEE_Param parameters[2]);
#endif /* DSEC_TEST */

/*!
 * \}
 */

#endif /* DSEC_TA_DIGEST_H */
