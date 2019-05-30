#
# DDS Security library
# Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

if(${PROJECT_NAME} STREQUAL "Project")
    message(FATAL_ERROR "Error: Do not use this CMakeLists.txt directly"
                        "Use the top-level CMakeLists.txt instead.")
endif()

set(OUTPUT_HEADER_FILE_DIR_TA ${CMAKE_CURRENT_BINARY_DIR} CACHE INTERNAL "")
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/modules/builtin_function.cmake)

function(dsec_embed_asset_ta_test_files)

    set(TARGET_NAME_TA builtins_ta_test)

    add_custom_target(${TARGET_NAME_TA})
    list(INSERT ARGN 0
         TARGET ${TARGET_NAME_TA}
         HEADER_FILE_DIR ${OUTPUT_HEADER_FILE_DIR_TA})

    dsec_embed_asset_files(${ARGN})

    add_dependencies(test-ta ${TARGET_NAME_TA})

endfunction()

function(dsec_embed_asset_ta_files)

    set(TARGET_NAME_TA builtins_ta)

    add_custom_target(${TARGET_NAME_TA})
    list(INSERT ARGN 0
         TARGET ${TARGET_NAME_TA}
         HEADER_FILE_DIR ${OUTPUT_HEADER_FILE_DIR_TA})

    dsec_embed_asset_files(${ARGN})

    add_dependencies(ta ${TARGET_NAME_TA})

endfunction()

unset(OUTPUT_HEADER_FILE_DIR_TA)
