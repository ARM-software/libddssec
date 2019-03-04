#
# DDS Security library
# Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
add_custom_target(builtins)
set(PREVIOUS_BUILTIN "")

# These variables are cached, so refer to the location of the CMake varibles at
# code-generation time. This means the same locations can be used when the
# functions in this file are used elsewhere in the project
set(BUILTIN_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "")
set(OUTPUT_HEADER_FILE_DIR ${CMAKE_CURRENT_BINARY_DIR} CACHE INTERNAL "")

# Generates a list of assets and metadata at [builddir]/builtins_list.h
#
# NAMES <name1;name2;name3> - List of builtin filenames used for:
#   * Name of the header files
#   * Name of the variables in the header files
#   Note: NAMES must not contain special characters or spaces. Any periods in
#   the filename (e.g. file.extension) will be converted to underscores (e.g.
#   file_extension) for the filename and the variable in the header. The name
#   field in the same struct will continue to use the period.
#
# LOCATION <location> - The location of the input files in the filesystem
function(dsec_embed_asset_ta_files)
    set(OPTIONS)
    set(ONE_VALUE_KEYWORDS LOCATION)
    set(MULTI_VALUE_KEYWORDS NAMES)
    cmake_parse_arguments(ARG_FILE
        "${OPTIONS}"
        "${ONE_VALUE_KEYWORDS}"
        "${MULTI_VALUE_KEYWORDS}"
        ${ARGN}
    )

    # Look for unknown arguments
    if(DEFINED ARG_FILE_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
            "Unknown arguments used with DSEC_EMBED_ASSET_TA_FILE():
            ${ARG_FILE_UNPARSED_ARGUMENTS}"
        )
    endif()

    # Builtin objects must have NAMES
    if(NOT DEFINED ARG_FILE_NAMES)
        message(FATAL_ERROR "Builtin objects must have NAMES.")
    endif()

    # Builtin object may have a LOCATION
    set(FILE_LOCATION ${CMAKE_CURRENT_SOURCE_DIR})
    if(DEFINED ARG_FILE_LOCATION)
        set(FILE_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/${ARG_FILE_LOCATION})
    endif()

    set(NAMES "")
    foreach(NAME ${ARG_FILE_NAMES})
        set(NAMES ${NAMES} ${FILE_LOCATION}/${NAME})
    endforeach()

    # A file called file.nare becomes a variable file_name.
    string(REPLACE "." "_" VARIABLE_NAMES "${ARG_FILE_NAMES}")
    set(OUTPUT_FILE builtins_list.h)

    add_custom_target(generate-builtin-header
        WORKING_DIRECTORY ${FILE_LOCATION}/
        COMMAND python ${CMAKE_SOURCE_DIR}/tools/embed_assets.py
            --input-files ${NAMES}
            --output-file ${OUTPUT_HEADER_FILE_DIR}/${OUTPUT_FILE}
            --filenames ${ARG_FILE_NAMES}
            --variable-names ${VARIABLE_NAMES}
            COMMENT "Generating builtin header"
        VERBATIM
    )
    add_dependencies(builtins generate-builtin-header)

endfunction()
