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

add_subdirectory(builtins)

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
        dsec_test_ta.c
        dsec_test_canary.c
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
    NAME shared_secret
    SOURCE
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ssh.c
        ${CMAKE_SOURCE_DIR}/src/dsec_hh.c
        ${CMAKE_SOURCE_DIR}/src/dsec_hh_dh.c
        dsec_test_ta.c
        test_ssh.c
)

dsec_embed_asset_ta_files(
    LOCATION "./assets"
    NAMES
        cacert.pem
        p1cert.pem
        p1privkey.pem
        invalid_cacert_empty.pem
        invalid_cacert_missing_byte.pem
        invalid_cacert_mismatch1.pem
        invalid_cacert_mismatch2.pem
        invalid_p1_cert_shortterm_signed.pem
        invalid_shortterm_ca.pem
        invalid_nosignature_cert.pem
        invalid_signature_cert.pem
)

dsec_embed_asset_test_files(
    LOCATION "./assets"
    NAMES
        p1cert.pem
        invalid_p1_cert_shortterm_signed.pem
        invalid_shortterm_ca.pem
        invalid_nosignature_cert.pem
        invalid_signature_cert.pem
        p1privkey.pem
)
