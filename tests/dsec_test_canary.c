/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_test_canary.h>
#include <assert.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * The following memory layout is used:
 *
 * +-------------+
 * | Canary-high |
 * +-------------+
 * | User's data |
 * +-------------+ <= Address returned to the user.
 * | Canary-low  |
 * +-------------+
 * | Padding     |
 * +-------------+
 * | Data size   |
 * +-------------+ Low memory
 *
 * Notes:
 *  - 'Data size' is used to calculate where 'Canary-high' starts.
 *  - 'Padding' is calculated during run-time and is used (when required) to
 *    ensure the 'User's data' starts on an address aligned on max_align_t. This
 *    is the same alignment requirement imposed on malloc().
 */

/*
 * Distinctive pattern used either side of buffer parameters to identify
 * clobbering
 */
static const uint8_t canary[] = { 0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF,
                                  0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF,
                                  0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF,
                                  0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF,
                                  0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF,
                                  0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF,
                                  0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF,
                                  0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF };

static const size_t canary_size = sizeof(canary);

#define ALIGN_NEXT(VALUE, INTERVAL) \
    ((((VALUE) + (INTERVAL) - 1) / (INTERVAL)) * (INTERVAL))

/*
 * Return the number of bytes required to ensure the user's data is aligned on
 * max_align_t (same alignment returned by malloc()).
 */
static size_t padding_size(void)
{
    const size_t size = canary_size + alignof(size_t);
    return ALIGN_NEXT(size, alignof(max_align_t)) - size;
}

/*
 * Finds the address returned by malloc in dsec_test_canary_alloc using the
 * known quantities of the canary's size, the size of the size metadata, and
 * any padding
 */
static void* data_to_buffer(void* data)
{
    intptr_t buffer_address = (intptr_t)data -
                       (sizeof(size_t) +
                       padding_size() +
                       canary_size);

    if (buffer_address < 0) {
        buffer_address = 0;
    }

    return (void*)buffer_address;
}

/*
 * Finds the address of the canary placed before the data section from the
 * address returned by malloc in dsec_test_canary_alloc
 */
static void* buffer_to_low_canary(void* buffer)
{
    return (void*)((uintptr_t)buffer + sizeof(size_t) + padding_size());
}

/*
 * Finds the address of the data section from the address returned by malloc in
 * dsec_test_canary_alloc
 */
static void* buffer_to_data(void* buffer)
{
    return (void*)((uintptr_t)buffer_to_low_canary(buffer) + canary_size);
}

/*
 * Finds the address of the canary placed after the data section from the
 * address returned by malloc in dsec_test_canary_alloc
 */
static void* buffer_to_high_canary(void* buffer, size_t size)
{
    return (void*)((uintptr_t)buffer_to_data(buffer) + size);
}

void* dsec_test_canary_alloc(size_t size)
{
    /*
     * Allocates space for the user's memory surrounded by a canary on each
     * side and prepended by a size_t representing the size of the user's data
     *
     *  Given the address of the returned buffer, all the other addresses can
     *  be inferred.
     */

    void* buffer = malloc(sizeof(size_t) +
                          padding_size() +
                          canary_size +
                          size +
                          canary_size);

    /*
     * The address that is returned to the user must be aligned on the same
     * boundary as max_align_t
     */
    assert(((uintptr_t)buffer_to_data(buffer) %
            (uintptr_t)alignof(max_align_t)) == 0);

    /*
     * If allocation fails, handle it in the calling function. This will
     * probably just make the test give a false negative
     */
    if (buffer == NULL) {
        return NULL;
    }

    /* Copy the size parameter to the bottom of the allocated buffer */
    memcpy(buffer, &size, sizeof(size_t));

    /* Copy the canaries to surround the area to be returned to the user */
    memcpy(buffer_to_low_canary(buffer), canary, canary_size);
    memcpy(buffer_to_high_canary(buffer, size), canary, canary_size);

    /*
     * Not the address returned by malloc, this is the address of the space for
     * the user's data
     */
    return buffer_to_data(buffer);
}

int dsec_test_canary_check(void* ptr)
{
    int status = DSEC_SUCCESS;
    void* buffer = data_to_buffer(ptr);

    if (buffer == NULL) {
        status = DSEC_E_PARAM;
    } else {
        /* The size metadata is at the bottom of the allocated buffer. */
        size_t size = *(size_t*)buffer;

        /* Compare the lower canary */
        if (memcmp(buffer_to_low_canary(buffer), canary, canary_size) != 0) {
            status = DSEC_E_DATA;
        }

        /* Compare the upper canary */
        if (memcmp(buffer_to_high_canary(buffer, size),
                   canary,
                   canary_size) != 0) {
            status = DSEC_E_DATA;
        }
    }

    return status;
}

void dsec_test_canary_free(void* ptr)
{
    free(data_to_buffer(ptr));
}
