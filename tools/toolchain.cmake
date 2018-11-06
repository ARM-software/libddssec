#
# DDS Security library
# Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

if("$ENV{TARGET_ARCH}" STREQUAL "")
    set(TARGET_ARCH aarch64)
else()
    set(TARGET_ARCH $ENV{TARGET_ARCH})
endif()

if("$ENV{CROSS_COMPILE}" STREQUAL "")
    set(CROSS_COMPILE aarch64-linux-gnu-)
else()
    set(CROSS_COMPILE $ENV{CROSS_COMPILE})
endif()

message(STATUS "Using TARGET_ARCH=${TARGET_ARCH}")
message(STATUS "Using CROSS_COMPILE=${CROSS_COMPILE}")

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR ${TARGET_ARCH})
set(CMAKE_C_COMPILER ${CROSS_COMPILE}gcc)
set(CMAKE_CXX_COMPILER ${CROSS_COMPILE}g++)
