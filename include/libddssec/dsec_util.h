/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DSEC_UTIL_H
#define DSEC_UTIL_H

#include <assert.h>

/*!
 * \defgroup GroupUtil Utility functions and macros
 * \{
 */

/*!
 * \brief Get the number of elements in an array.
 *
 * \param ARRAY Array.
 *
 * \return The number of elements in the array.
 */
#define DSEC_ARRAY_SIZE(ARRAY) \
    __builtin_choose_expr( \
        __builtin_types_compatible_p( \
            __typeof(ARRAY), \
            __typeof(&(ARRAY)[0])), \
        (void)0, \
        (sizeof(ARRAY) / sizeof((ARRAY)[0])))

#endif /* DSEC_UTIL_H */

/*!
 * \}
 */
