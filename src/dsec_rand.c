/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_rand.h>

#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

int dsec_rand(void* buffer, size_t nbytes)
{
    int bytes_read = 0;
    int result = 0;

    if ((buffer != NULL) && (nbytes != 0UL) && (nbytes <= 256UL)) {
        bytes_read = syscall(SYS_getrandom, buffer, nbytes, 0 /* flags */);

        if (bytes_read >= 0) {
            /*
             * Reading up to 256 bytes should always return all the data in one
             * call.
             */
            if (bytes_read == ((int)nbytes)) {
                result = DSEC_SUCCESS;
            } else {
                assert(false);
                result = DSEC_E_DATA;
            }
        } else {
            result = DSEC_E_DATA;
        }
    } else {
        result = DSEC_E_PARAM;
    }

    return result;
}
