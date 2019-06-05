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
include(../../cmake/modules/builtin_function.cmake)

function(dsec_embed_asset_ta_files ta target)

    add_custom_target(${target})
    list(INSERT ARGN 0
         TARGET ${target}
         HEADER_FILE_DIR ${OUTPUT_HEADER_FILE_DIR_TA})

    dsec_embed_asset_files(${ARGN})

    add_dependencies(${ta} ${target})

endfunction()

unset(OUTPUT_HEADER_FILE_DIR_TA)
