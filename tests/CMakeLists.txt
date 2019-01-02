#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

dsec_add_test(NAME rand SOURCE test_rand.c ${CMAKE_SOURCE_DIR}/src/dsec_rand.c)
dsec_add_test(NAME version SOURCE test_version.c)
