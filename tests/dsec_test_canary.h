/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * \file
 * \brief \copybrief GroupTest
 */

#ifndef DSEC_TEST_CANARY_H
#define DSEC_TEST_CANARY_H

#include <stddef.h>
#include <stdint.h>

/*!
 * \defgroup GroupTest Test
 *
 * \brief Test suite framework canary utilities
 *
 * \details This set of utilities allows creation of an allocated section of
 *      memory surrounded by distinctive 'canary' values. By checking these
 *      values after the allocated memory has been used, we can ensure that the
 *      function using the buffer does not clobber surrounding memory
 *      locations.
 *
 *      To use these utilities:
 *          - Allocate a section of memory for the function using
 *          dsec_test_canary_alloc
 *          - Pass the pointer to the allocated memory to the test target
 *          - Pass the pointer to dsec_test_canary_check to see if it has been
 *          inadvertently changed
 *          - Free the memory with dsec_test_canary_free
 *
 * @{
 */

/*!
 * \brief Surround a location of memory with distinctive patterns.
 *
 * \details This function is used to create a section of memory containing the
 *     data to be used for testing surrounded by a distinctive pattern (the
 *     'canaries'). If the area surrounding the data is accidentally written to,
 *     this pattern will be overwritten. If the area surrounding the data is
 *     accidentally read from, this pattern may show up in the error message.
 *
 * \param size The number of bytes in the buffer.
 *
 * \return A pointer to the memory location for the test data to be copied in
 *     to.
 * \retval NULL If allocation fails
 */
void* dsec_test_canary_alloc(size_t size);

/*!
 * \brief Check that the distinctive patterns have not been altered.
 *
 * \details This function asserts that the data in the low_canary and
 *     high_canary of canaried_buffer is the same as the distinctive pattern.
 *
 * \param ptr A pointer to the canaried data allocated with
 *     dsec_test_canary_alloc().
 *
 * \retval ::DSEC_SUCCESS Success.
 * \retval ::DSEC_E_PARAM Invalid buffer address
 */
int dsec_test_canary_check(void* ptr);

/*!
 * \brief Free the memory allocated for the canaries.
 *
 * \param ptr A pointer to the canaried data allocated with
 *     dsec_test_canary_alloc().
 *
 * \return None.
 */
void dsec_test_canary_free(void* ptr);

/*!
 * \}
 */

#endif /* DSEC_TEST_CANARY_H */
