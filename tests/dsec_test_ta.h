/*
 * DDS Security library
 * Copyright (c) 2018-2020, Arm Limited and Contributors. All rights reserved.
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
 * \retval ::DSEC_SUCCESS Success. The backed-up assets have been replaced,
 *     tee-supplicant has been killed, and the secure-storage has been wiped.
 * \retval ::DSEC_E_DATA The secure storage was not cleared.
 * \retval ::DSEC_E_ACCESS The TA could not be removed.
 * \retval ::DSEC_E_ACCESS The secure storage directory could not be removed.
 * \retval ::DSEC_E_ACCESS The TA directory could not be removed.
 */
int dsec_test_ta_teardown(void);

/*!
 * \}
 */

#endif /* DSEC_TEST_TA_H */
