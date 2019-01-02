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

/*! Invalid size */
#define DSEC_E_SIZE          -2

/*! Invalid handler or callback */
#define DSEC_E_HANDLER       -3

/*! Invalid access or permission denied */
#define DSEC_E_ACCESS        -4

/*! Value out of range */
#define DSEC_E_RANGE         -5

/*! Operation timed out */
#define DSEC_E_TIMEOUT       -6

/*! Memory allocation failed */
#define DSEC_E_NOMEM         -7

/*! Not supported or disabled */
#define DSEC_E_SUPPORT       -8

/*! Handler or resource busy */
#define DSEC_E_BUSY          -9

/*! Unexpected or invalid data */
#define DSEC_E_DATA          -10

/*! Accessing an uninitialized resource */
#define DSEC_E_INIT          -11

/*!
 * \}
 */

#endif /* DSEC_ERRNO_H */
