/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * \file
 * \brief \copybrief GroupTest
 */

#ifndef DSEC_TEST_H
#define DSEC_TEST_H

#include <assert.h>
#include <stdnoreturn.h>

/*!
 * \defgroup GroupTest Test
 *
 * \brief Test suite framework
 * @{
 */

/*!
 * \brief Define a test case description.
 *
 * \param FUNC Test case function name.
 *
 * \return A test case description.
 */
#define DSEC_TEST_CASE(FUNC) \
    { \
        .name = #FUNC, \
        .test_execute = FUNC \
    }

/*!
 * \brief Test case descriptor.
 */
struct dsec_test_case_desc {
    /*! Test case name */
    const char *name;

    /*!
     * \brief Pointer to the test case execution function.
     *
     * \return None.
     *
     * \note A test case is identified as having successfully completed if
     *      execution returns from this function. Test case execution functions
     *      should use the assert() macro from the C standard library to check
     *      test conditions.
     */
    void (*test_execute)(void);
};

/*!
 * \brief Test suite description.
 */
struct dsec_test_suite_desc {
    /*! Test suite name */
    const char *name;

    /*!
     * \brief Pointer to a test suite setup function.
     *
     * \details This function should be used to initialize and configure a test
     *      fixture or to execute expensive routines that could otherwise be
     *      done within a test case setup function.
     *
     * \retval ::DSEC_SUCCESS The test suite environment was successfully set
     * up.
     * \return Any of the other error codes defined by the framework.
     *
     * \note May be NULL, in which case the test suite is considered to have no
     *      setup function. In the event that test suite setup fails, the test
     *      suite is not executed.
     */
    int (*test_suite_setup)(void);

    /*!
     * \brief Pointer to a test suite teardown function.
     *
     * \retval ::DSEC_SUCCESS The test suite environment was successfully torn
     *     down.
     * \return Any of the other error codes defined by the framework.
     *
     * \note May be NULL, in which case the test suite is considered to have no
     *      teardown function.
     */
    int (*test_suite_teardown)(void);

    /*!
     * \brief Pointer to a test case setup function.
     *
     * \details This function should be used to ensure test cases are running in
     *      a known, sane environment prior to execution.
     *
     * \retval ::DSEC_SUCCESS The test case environment was successfully set up.
     * \return Any of the other error codes defined by the framework.
     *
     * \note May be NULL, in which case the test case is considered to have no
     *      setup function.
     */
    int (*test_case_setup)(void);

    /*!
     * \brief Pointer to a test case teardown function.
     *
     * \retval ::DSEC_SUCCESS The test case environment was successfully torn
     *     down.
     * \return Any of the other error codes defined by the framework.
     *
     * \note May be NULL, in which case the test case is considered to have no
     *      teardown function.
     */
    int (*test_case_teardown)(void);

    /*! Number of test cases */
    unsigned int test_case_count;

    /*! Pointer to array of test cases */
    const struct dsec_test_case_desc *test_case_table;
};

/*!
 * \brief Unit test assertion macro.
 *
 * \details If the expression evaluates to false the unit test fails. The test
 *      framework prints the details on where the assertion occurred and the
 *      test case is immediately terminated.
 *
 * \param EXPRESSION Expression to be evaluated.
 *
 * \return None.
 */
#define DSEC_TEST_ASSERT(EXPRESSION) \
    __extension__({ \
        if (!(EXPRESSION)) \
            __dsec_test_assert_fail(#EXPRESSION, __FILE__, __LINE__, \
                __func__); \
    })

/*!
 * \brief Process an unit test assertion.
 *
 * \details This function is used internally by \ref DSEC_TEST_ASSERT to print
 *      out the details on where the assert occurred. This function is also
 *      responsible for stopping the test case execution.
 *      This function never returns.
 *
 * \param assertion String containing the expression that asserted.
 *
 * \param file Name of the file where the assert occurred.
 *
 * \param line Line number where the assert occurred.
 *
 * \param function Name of the function where the assert occurred.
 *
 * \return None.
 *
 * \internal
 * \note This function must not be called directly from the test cases.
 */
noreturn void __dsec_test_assert_fail(const char *assertion, const char *file,
    unsigned int line, const char *function);

/*!
 * \}
 */

#endif /* DSEC_TEST_H */
