/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DSEC_TA_H
#define DSEC_TA_H

/*!
 * \addtogroup GroupTA Trusted Application
 * \{
 */

#ifndef DSEC_TA_UUID
    #error "DSEC_TA_UUID not defined"
#endif /* DSEC_TA_UUID */

#if DSEC_TEST
enum {
    DSEC_TA_CMD_PLACEHOLDER = 1,
};
#endif /* DSEC_TEST */

/*!
 * \}
 */

#endif /* DSEC_TA_H */
