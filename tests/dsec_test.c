/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_test.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* Test information provided by the test suite */
extern const struct dsec_test_suite_desc test_suite;

static jmp_buf test_buf_context;

noreturn void __dsec_test_assert_fail(const char *assertion,
    const char *file, unsigned int line, const char *function)
{
    printf("Assertion failed: %s\n", assertion);
    printf("    Function: %s\n", function);
    printf("    File: %-66s\n", file);
    printf("    Line: %d\n", line);
    longjmp(test_buf_context, !DSEC_SUCCESS);
}

static void print_separator(void)
{
    printf("----------------------------------------");
    printf("----------------------------------------\n");
}

static void print_prologue(void)
{
    printf("\nStarting tests for %s\n", test_suite.name);
    print_separator();
}

static void print_epilogue(unsigned int successful_tests)
{
    int pass_rate = (successful_tests * 100) / test_suite.test_case_count;

    print_separator();
    printf("%u / %u passed (%d%% pass rate)\n\n", successful_tests,
        test_suite.test_case_count, pass_rate);
}

static void print_result(const char *name, bool success)
{
    /* The name is truncated to 72 characters */
    printf("%-72s %s\n", name, (success ? "SUCCESS" : "FAILURE"));
}

static unsigned int run_tests(unsigned int* successful_tests_ptr)
{
    unsigned int i;
    unsigned int* volatile successful_tests = successful_tests_ptr;
    const struct dsec_test_case_desc *test_case;
    int error = DSEC_SUCCESS;
    *successful_tests = 0;

    if (test_suite.test_suite_setup != NULL) {
        error = test_suite.test_suite_setup();
        if (error != DSEC_SUCCESS) {
            fprintf(stderr,
                    "\nTest suite setup failed with error %d\n", error);

            return error;
        }
    }

    for (i = 0; i < test_suite.test_case_count; i++) {
        bool success = true;
        test_case = &test_suite.test_case_table[i];

        if ((test_case->test_execute == NULL) || (test_case->name == NULL)) {
            print_result("Test case undefined!", false);

            continue;
        }

        if (test_suite.test_case_setup != NULL) {
            error = test_suite.test_case_setup();
            if (error != DSEC_SUCCESS) {
                success = false;
                fprintf(stderr,
                        "\nTest case setup for test case:\n%s\n"
                        "failed with error %d\n",
                        test_case->name,
                        error);
            }
        }

        /*
         * The setjmp function stores the execution context of the processor at
         * that point in time. When called, 0 is returned by default.
         * If an assertion fails in the test case following, execution returns
         * to an undefined point within setjmp() which then returns a non-zero
         * value. See __assert_fail() for exactly how assertion failure is
         * handled.
         */
        if (success && (setjmp(test_buf_context) == DSEC_SUCCESS)) {
            test_case->test_execute();

            success = true;
        } else
            success = false;

        if (test_suite.test_case_teardown != NULL) {
            error = test_suite.test_case_teardown();
            if (error != DSEC_SUCCESS) {
                success = false;
                fprintf(stderr,
                        "\nTest case teardown for test case:\n%s\n"
                        "failed with error %d\n",
                        test_case->name,
                        error);
            }
        }

        if (success) {
            (*successful_tests)++;
        }

        print_result(test_case->name, success);
    }

    if (test_suite.test_suite_teardown != NULL) {
        error = test_suite.test_suite_teardown();
        if (error != DSEC_SUCCESS) {
            fprintf(stderr,
                    "\nTest case teardown for test case:\n%s\n"
                    "failed with error %d\n",
                    test_case->name,
                    error);
            return error;
        }
    }

    return error;
}

int main(void)
{
    unsigned int successful_tests;
    if (test_suite.test_case_count != 0) {
        int error = 0;
        print_prologue();
        error = run_tests(&successful_tests);
        print_epilogue(successful_tests);

        if ((successful_tests != test_suite.test_case_count) ||
            (error != DSEC_SUCCESS))
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
