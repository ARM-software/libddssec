/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_digest.h
 * Source code for performing a SHA256 digest.
 */

#ifndef DSEC_DIGEST_H
#define DSEC_DIGEST_H

/*!
 * \defgroup GroupHash Hash Generation
 * \{
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <dsec_ca.h>

/*!
 * \brief Perform a SHA256 digest
 *
 * \details Calls the Trusted Application to perform a SHA256 digest on the
 *     input buffer.
 *
 * \param [out] digest Digest of the input.
 * \param [out] digest_size Size of the returned digest, updated in the
 *     function.
 * \param input Message to be hashed.
 * \param input_size Size of the message to be hashed.
 * \param instance Initialized instance to access the Trusted Application.
 *
 * \retval ::DSEC_SUCCESS Digest is returned.
 * \retval ::DSEC_E_PARAM Given parameters are invalid.
 */
int32_t dsec_sha256(uint8_t* digest,
                    uint32_t* digest_size,
                    const uint8_t* input,
                    uint32_t input_size,
                    const struct dsec_instance* instance);


/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_DIGEST_H */
