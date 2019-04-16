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
