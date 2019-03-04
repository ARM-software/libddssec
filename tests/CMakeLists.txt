#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

dsec_add_test(NAME canary SOURCE test_canary.c)
dsec_add_test(NAME rand SOURCE test_rand.c ${CMAKE_SOURCE_DIR}/src/dsec_rand.c)
dsec_add_test(NAME version SOURCE test_version.c)
dsec_add_test(
    NAME ca_common_functions
    SOURCE test_ca_common_functions.c ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
)
