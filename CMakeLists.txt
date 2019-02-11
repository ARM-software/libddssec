#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

cmake_minimum_required(VERSION 3.5)
project("libddssec" VERSION 0.1.0 LANGUAGES C)
set(${PROJECT_NAME}_DESCRIPTION_SUMMARY "DDS Security library")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake/modules)

message(STATUS
    "${${PROJECT_NAME}_DESCRIPTION_SUMMARY} version ${PROJECT_VERSION}"
)

# Toolchain options
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(COMPILE_OPTIONS
    -Wall
    -Wextra
    -Werror
    -Wno-missing-field-initializers
    -Wno-unused-parameter
    -pedantic
    -pedantic-errors
)

#
# Generate version header
#
set(version_header ${CMAKE_CURRENT_BINARY_DIR}/include/dsec_version.h)
message(STATUS "Generating version header in ${version_header}")
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/${PROJECT_NAME}/dsec_version.h.in
    ${version_header}
)

#
# Settings for OP-TEE
#
find_package(OPTEECLIENT REQUIRED)

#
# Source files
#
set(PROJECT_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/${PROJECT_NAME}
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/trusted_application/include
)

# Files from external libraries which need to be included in the source but
# which don't need to be checked for documentation.
set(EXTERNAL_INCLUDES
)

set(PROJECT_SOURCE
    src/dsec_rand.c
)

#
# Trusted Application
#
set(DSEC_TA_UUID
    "{0x8ee919be,0x3954,0x4170,{0xb4,0xc2,0xda,0x16,0x9f,0x39,0x53,0x6e}}"
)
set(DSEC_TA_UUID_STRING "8ee919be-3954-4170-b4c2-da169f39536e")

list(APPEND COMPILE_DEFINITIONS
    -DDSEC_TA_UUID=${DSEC_TA_UUID}
    -DDSEC_TA_UUID_STRING="${DSEC_TA_UUID_STRING}"
)

add_subdirectory(trusted_application)

#
# Test support
#
set(TEST_COMPILE_OPTIONS ${COMPILE_OPTIONS})

#
# Function to declare a test suite:
#
# NAME <name> - Test suite name used for:
#   * Name of the executable
#   * Name of the target in the build system (e.g. make <name>)
#   * Name used in the the logs when running 'make build_and_test'
#   Note: NAME must not contain special characters or spaces. Name must not
#       conflict other project targets (e.g. clean, all, libddssec, etc).
#
# SOURCE <source1> [source2 ...] - Source code to be included in the build
#   of the test. At least one source code must be passed in.
#
# WRAP [function_name1 ...] - Functions being "wrapped". A wrapped function
#   requires the test case to provide its implementation. See the '--wrap'
#   argument in # 'GNU ld' for more details. This argument can be empty.
#
function(dsec_add_test)
    set(options)
    set(one_value_keywords NAME)
    set(multi_value_keywords SOURCE WRAP)
    cmake_parse_arguments(
        ARG_TEST
        "${options}"
        "${one_value_keywords}"
        "${multi_value_keywords}"
        ${ARGN}
    )

    # Test must have a NAME
    if(NOT DEFINED ARG_TEST_NAME)
        message(FATAL_ERROR "Test suite must have a NAME.")
    endif()

    # Test must have at least one source code
    list(LENGTH ARG_TEST_SOURCE source_count)
    if(${source_count} EQUAL 0)
        message(FATAL_ERROR "Test suite must have at least one source code.")
    endif()

    # Look for unknown arguments
    if(DEFINED ARG_TEST_UNPARSED_ARGUMENTS)
        string(CONCAT ERROR_MSG
            "Unknown arguments used with dsec_add_test(): "
            "'${ARG_TEST_UNPARSED_ARGUMENTS}'"
        )
        message(FATAL_ERROR ${ERROR_MSG})
    endif()

    add_executable(${ARG_TEST_NAME} ${TEST_SOURCES} ${ARG_TEST_SOURCE})
    target_link_libraries(${ARG_TEST_NAME} OPTEECLIENT::OPTEECLIENT)
    target_compile_options(${ARG_TEST_NAME} PRIVATE ${TEST_COMPILE_OPTIONS})
    target_compile_definitions(
        ${ARG_TEST_NAME}
        PRIVATE
            ${TEST_COMPILE_DEFINITIONS}
    )
    target_include_directories(
        ${ARG_TEST_NAME}
        PUBLIC
            ${EXTERNAL_INCLUDES}
            ${PROJECT_INCLUDES}
            ${TEST_INCLUDES}
    )
    add_test(${ARG_TEST_NAME} ${ARG_TEST_NAME})
    add_dependencies(build_and_test ${ARG_TEST_NAME})
endfunction()

enable_testing()
add_custom_target(build_and_test ${CMAKE_CTEST_COMMAND} -V)
set(TEST_SOURCES dsec_test.c dsec_test_ta.c)
set(TEST_INCLUDES ${INCLUDES} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
set(DSEC_TA_LOCATION_DIR "${CMAKE_CURRENT_BINARY_DIR}/trusted_application")
set(DSEC_TA_LOCATION "${DSEC_TA_LOCATION_DIR}/${DSEC_TA_UUID_STRING}.ta")
set(DSEC_TA_DESTINATION_DIR "/lib/optee_armtz")
set(DSEC_TA_DESTINATION "${DSEC_TA_DESTINATION_DIR}/${DSEC_TA_UUID_STRING}.ta")
list(APPEND TEST_COMPILE_DEFINITIONS
    -DDSEC_TA_LOCATION_DIR="${DSEC_TA_LOCATION_DIR}"
    -DDSEC_TA_LOCATION="${DSEC_TA_LOCATION}"
    -DDSEC_TA_DESTINATION_DIR="${DSEC_TA_DESTINATION_DIR}"
    -DDSEC_TA_DESTINATION="${DSEC_TA_DESTINATION}"
)
add_subdirectory(tests)

#
# Documentation
#
add_subdirectory(doc)

#
# Library settings
#
add_library(${PROJECT_NAME} SHARED ${PROJECT_SOURCE})
target_link_libraries(${PROJECT_NAME} OPTEECLIENT::OPTEECLIENT)
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})
target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
        ${EXTERNAL_INCLUDES}
        ${PROJECT_INCLUDES}
)
