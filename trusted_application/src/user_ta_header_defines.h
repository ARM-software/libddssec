/*
 * DDS Security library
 * Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <dsec_ta.h>

#define TA_UUID DSEC_TA_UUID

#define TA_FLAGS (TA_FLAG_USER_MODE | \
                  TA_FLAG_EXEC_DDR)

#define TA_STACK_SIZE (2 * 1024)
#define TA_DATA_SIZE  (32 * 1024)

#define TA_DESCRIPTION "DSEC_PROJECT_DESCRIPTION_SUMMARY"
#define TA_VERSION "DSEC_PROJECT_VERSION"

#endif /* USER_TA_HEADER_DEFINES_H */
