/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *     Standard return codes.
 */

#ifndef DSEC_ERRNO_H
#define DSEC_ERRNO_H

/*!
 * \defgroup GroupErrno Return Codes
 * \{
 */

/*! Success */
#define DSEC_SUCCESS          0

/*! Invalid parameter(s) */
#define DSEC_E_PARAM         -1

/*! Invalid access or permission denied */
#define DSEC_E_ACCESS        -2

/*! Not supported or disabled */
#define DSEC_E_SUPPORT       -3

/*! Unexpected, uninitialized or invalid data */
#define DSEC_E_DATA          -4

/*! Accessing an uninitialized resource */
#define DSEC_E_INIT          -5

/*! TEE interaction failed */
#define DSEC_E_TEE           -6

/*! Requested item/data not found */
#define DSEC_E_NOT_FOUND     -7

/*! Data is not the correct type and cannot be parsed */
#define DSEC_E_BAD_FORMAT    -8

/*! No more memory or memory allocation failed */
#define DSEC_E_MEMORY        -9

/*! Verification of a signature failed or error within the authentication */
#define DSEC_E_SECURITY      -10

/*! Given buffer is too small */
#define DSEC_E_SHORT_BUFFER  -11

/*!
 * \}
 */

#endif /* DSEC_ERRNO_H */
