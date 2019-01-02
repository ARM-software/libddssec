/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * \file
 * \brief \copybrief GroupRand
 */

#ifndef DSEC_RAND_H
#define DSEC_RAND_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \defgroup GroupRand Random
 *
 * \brief Random number generation API.
 * \{
 */

/*!
 * \brief Fill a buffer with random data.
 *
 * \details Fill a buffer with up to 256 bytes of random data.
 *
 * \param[out] buffer Pointer to storage where random data will be written to.
 *
 * \param nbytes Number of random data in bytes. Must be bigger than 0. Must be
 *      no more than 256 bytes.
 *
 * \retval ::DSEC_SUCCESS Success.
 * \retval ::DSEC_E_PARAM buffer pointer is invalid (NULL).
 * \retval ::DSEC_E_PARAM nbytes is zero or more than 256.
 * \retval ::DSEC_E_DATA The system failed to generate random data.
 */
int dsec_rand(void *buffer, size_t nbytes);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif

#endif /* DSEC_RAND_H */
