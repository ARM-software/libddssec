#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

if(${PROJECT_NAME} STREQUAL "Project")
    message(FATAL_ERROR "Error: Do not use this CMakeLists.txt directly"
                        "Use the top-level CMakeLists.txt instead.")
endif()

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
    set(multi_value_keywords SOURCE WRAP DEPENDENCIES)
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

    if(DEFINED ARG_TEST_DEPENDENCIES)
        add_dependencies(${ARG_TEST_NAME} ${ARG_TEST_DEPENDENCIES})
    endif()

    add_dependencies(build_and_test ${ARG_TEST_NAME})
endfunction()


add_subdirectory(builtins)

# Enable the tests
add_custom_target(build_and_test
    ${CMAKE_CTEST_COMMAND}
        --verbose
        --timeout 360
)

# Test source used for the base framework
set(TEST_SOURCES dsec_test.c dsec_test_ta.c dsec_test_canary.c)
# Test includes
set(TEST_INCLUDES
    ${INCLUDES}
    ./
    ${CMAKE_CURRENT_BINARY_DIR}
)

# Specific compile option and definition for the tests.
set(TEST_COMPILE_OPTIONS ${COMPILE_OPTIONS})
set(TEST_COMPILE_DEFINITIONS ${COMPILE_DEFINITIONS})

# Tests needs the location of the TA and its destination as the framework will
# do the copy on the device running the tests.
set(DSEC_TA_LOCATION_DIR build)
set(DSEC_TA_LOCATION "${DSEC_TA_LOCATION_DIR}/${DSEC_TA_UUID_STRING}.ta")
set(DSEC_TA_DESTINATION_DIR "/lib/optee_armtz")
set(DSEC_TA_DESTINATION "${DSEC_TA_DESTINATION_DIR}/${DSEC_TA_UUID_STRING}.ta")
list(APPEND TEST_COMPILE_DEFINITIONS
    -DDSEC_TA_LOCATION="${DSEC_TA_LOCATION}"
    -DDSEC_TA_DESTINATION_DIR="${DSEC_TA_DESTINATION_DIR}"
    -DDSEC_TA_DESTINATION="${DSEC_TA_DESTINATION}"
    -DDSEC_TEST=1
)

# Definition of the tests

dsec_add_test(NAME canary SOURCE test_canary.c)
dsec_add_test(NAME version SOURCE test_version.c)
dsec_add_test(
    NAME ca_common_functions
    SOURCE test_ca_common_functions.c ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
)
dsec_add_test(
    NAME manage_object
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        test_manage_object.c
        test_manage_object_ca.c
)
dsec_add_test(
    NAME identity_handle
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ih.c
        dsec_test_ta.c
        test_ih.c
)
dsec_add_test(
    NAME digest
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        dsec_digest_ca.c
        dsec_test_ta.c
        test_digest.c
)
dsec_add_test(
    NAME identity_handle_ca
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ih.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ih_ca.c
        dsec_test_ta.c
        test_ih_ca.c
)
dsec_add_test(
    NAME identity_handle_cert
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ih.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ih_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ih_cert.c
        dsec_test_ta.c
        test_ih_cert.c
    DEPENDENCIES
        builtins_test
)
dsec_add_test(
    NAME identity_handle_private_key
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ih.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ih_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ih_cert.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ih_privkey.c
        dsec_test_ta.c
        test_ih_privkey.c
)
dsec_add_test(
    NAME handshake_handle
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_hh.c
        dsec_test_ta.c
        test_hh.c
)
dsec_add_test(
    NAME diffie_hellman
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_hh.c
        ${CMAKE_SOURCE_DIR}/src/dsec_hh_dh.c
        dsec_test_ta.c
        test_hh_dh.c
)
dsec_add_test(
    NAME challenges
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_hh.c
        ${CMAKE_SOURCE_DIR}/src/dsec_hh_challenge.c
        test_hh_challenge.c
)
dsec_add_test(
    NAME shared_secret
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ssh.c
        ${CMAKE_SOURCE_DIR}/src/dsec_hh.c
        ${CMAKE_SOURCE_DIR}/src/dsec_hh_dh.c
        ${CMAKE_SOURCE_DIR}/src/dsec_hh_challenge.c
        test_ssh.c
)
dsec_add_test(
    NAME hmac_internal
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        test_hmac.c
)

dsec_embed_asset_test_files(
    FILE_PATH
        assets/p1cert.pem
        assets/invalid_p1_cert_shortterm_signed.pem
        assets/invalid_shortterm_ca.pem
        assets/invalid_nosignature_cert.pem
        assets/invalid_signature_cert.pem
        assets/p1privkey.pem
)

dsec_build_ta(
    TARGET_NAME
        test-ta
    TA_UUID_STRING
        ${DSEC_TA_UUID_STRING}
    FILE_PATH
        assets/cacert.pem
        assets/p1cert.pem
        assets/p1privkey.pem
        assets/invalid_cacert_empty.pem
        assets/invalid_cacert_missing_byte.pem
        assets/invalid_cacert_mismatch1.pem
        assets/invalid_cacert_mismatch2.pem
        assets/invalid_p1_cert_shortterm_signed.pem
        assets/invalid_shortterm_ca.pem
        assets/invalid_nosignature_cert.pem
        assets/invalid_signature_cert.pem
    BUILD_TEST_TA
)

# Add the test ta as a dependency for the tests.
add_dependencies(build_and_test test-ta)
