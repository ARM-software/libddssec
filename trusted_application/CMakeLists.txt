#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

if(${PROJECT_NAME} STREQUAL "Project")
    message(FATAL_ERROR "Error: Do not use trusted application's CMakeLists.txt\
        directly. Use the top-level CMakeLists.txt instead.")
endif()

add_custom_target(ta
        COMMAND make O=${CMAKE_CURRENT_BINARY_DIR}
        PROJECT_VERSION=${PROJECT_VERSION}
        PROJECT_DESCRIPTION_SUMMARY=${${PROJECT_NAME}_DESCRIPTION_SUMMARY}
        DSEC_TA_UUID=${DSEC_TA_UUID}
        DSEC_TA_UUID_STRING=${DSEC_TA_UUID_STRING}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
        COMMENT "Building trusted application"
        VERBATIM)

add_custom_target(ta-clean
        COMMAND make O=${CMAKE_CURRENT_BINARY_DIR} clean
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
        COMMENT "Cleaning trusted application"
        VERBATIM)
