/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * \file
 * \brief \copybrief GroupPrint
 */

#ifndef DSEC_PRINT_H
#define DSEC_PRINT_H

#include <stdarg.h>
#include <stdio.h>

/*!
 * \defgroup GroupPrint Printing functions for use in debugging
 * \{
 */

/*!
 * \brief Print a message.
 *
 * \details Print a message to STDERR when the library is built with the DEBUG
 *      flag enabled.
 *
 * \param fmt Const char pointer to the message format string.
 *
 * \param ... Optional additional arguments to be converted according the
 *      format string.
 *
 * \return On success, the number of characters written as an int. If DEBUG is
 *      disabled, 0 characters are printed so 0 is returned.
 * \return On failure, a negative value as in printf(3) specification.
 */
static inline int dsec_print(const char* fmt, ...)
{
    #if DEBUG
        va_list args;
        va_start(args, fmt);
        int retval = vfprintf(stderr, fmt, args);
        va_end(args);
        return retval;
    #else
        return 0;
    #endif
}

/*!
 * \}
 */

#endif /*  DSEC_PRINT_H */
