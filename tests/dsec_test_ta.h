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

#ifndef DSEC_TEST_TA_H
#define DSEC_TEST_TA_H

/*!
 * \defgroup GroupTest Test
 *
 * \brief Test suite Trusted Application helper functions
 * \{
 */

/*!
 * \brief Setup a defined Trusted Application (TA). Any existing file in the
 *      path is moved and backed up for safekeeping. Launches tee-supplicant.
 *
 * \retval ::DSEC_E_DATA if the TA location directory specified could not be
 *      created.
 * \retval ::DSEC_E_ACCESS if the TA location directory specified cannot be
 *      accessed or tee-supplicant cannot be found.
 * \retval ::DSEC_E_SUPPORT if the TA destination directory cannot be written
 *      to (i.e. the user is not root), if tee-supplicant can't be run, or for
 *      any other unexpected failure.
 * \retval ::DSEC_SUCCESS Success. The specified TA is ready for use and
 *      tee-supplicant has been launched.
 */
int dsec_test_ta_setup(void);

/*!
 * \brief Removes the Trusted Application (TA) created by dsec_test_ta_setup()
 *      and restores any file that was in its path before. Kills tee-supplicant.
 *
 * \return ::DSEC_E_ACCESS if the TA or its directory cannot be removed.
 * \return ::DSEC_SUCCESS if the TA or its directory were removed. If the backed
 *      up TA cannot be restored or tee-supplicant cannot be killed, the error
 *      code is still DSEC_SUCCESS as it is not concidered as a fatal error.
 */
int dsec_test_ta_teardown(void);

/*!
 * \}
 */

#endif /* DSEC_TEST_TA_H */
