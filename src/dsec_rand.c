/*
 * DDS Security library
 * Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <syscall.h>
#include <unistd.h>
#include <linux/random.h>
#include <dsec_errno.h>
#include <dsec_rand.h>

int dsec_rand(void *buffer, size_t nbytes)
{
    int bytes_read;

    if ((buffer == NULL) || (nbytes == 0) || (nbytes > 256))
        return DSEC_E_PARAM;

    bytes_read = syscall(SYS_getrandom, buffer, nbytes, 0);

    if (bytes_read < 0)
        return DSEC_E_DATA;

    /* Reading up to 256 bytes should always return all the data in one call */
    if (bytes_read != ((int)nbytes)) {
        assert(false);
        return DSEC_E_DATA;
    }

    return DSEC_SUCCESS;
}
