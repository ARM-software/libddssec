#
# DDS Security library
# Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Generates a list of assets and metadata at [builddir]/builtins_list.h specific
# to the Trusted Application.
#
# NAMES <name1;name2;name3> - List of builtin filenames used for:
#   * Name of the header files
#   * Name of the variables in the header files
#   Note: NAMES must not contain special characters or spaces. Any periods in
#   the filename (e.g. 'file.extension') will be converted to underscores (e.g.
#   'file_extension') for the filename and the variable in the header.
#
# LOCATION <location> - The location of the input files in the filesystem
function(dsec_embed_asset_files)
    set(OPTIONS)
    set(ONE_VALUE_KEYWORDS LOCATION TARGET HEADER_FILE_DIR)
    set(MULTI_VALUE_KEYWORDS NAMES)
    cmake_parse_arguments(ARG_BUILTIN
        "${OPTIONS}"
        "${ONE_VALUE_KEYWORDS}"
        "${MULTI_VALUE_KEYWORDS}"
        ${ARGN}
    )

    # Look for unknown arguments
    if(DEFINED ARG_BUILTIN_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
            "Unknown arguments used with DSEC_EMBED_ASSET_TA_FILE():
            ${ARG_BUILTIN_UNPARSED_ARGUMENTS}"
        )
    endif()

    # Builtin objects must have NAMES
    if(NOT DEFINED ARG_BUILTIN_NAMES)
        message(FATAL_ERROR "Builtin objects must have NAMES.")
    endif()

    if(NOT DEFINED ARG_BUILTIN_TARGET)
        message(FATAL_ERROR "Builtin objects must have a valid TARGET.")
    endif()

    if(NOT DEFINED ARG_BUILTIN_HEADER_FILE_DIR)
        message(FATAL_ERROR "Builtin objects must have a output directory:
                HEADER_FILE_DIR")
    endif()

    # Builtin object may have a LOCATION
    set(FILE_LOCATION ${CMAKE_CURRENT_SOURCE_DIR})
    if(DEFINED ARG_BUILTIN_LOCATION)
        set(FILE_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/${ARG_BUILTIN_LOCATION})
    endif()

    set(NAMES "")
    foreach(NAME ${ARG_BUILTIN_NAMES})
        set(NAMES ${NAMES} ${FILE_LOCATION}/${NAME})
    endforeach()

    string(REPLACE "." "_" VARIABLE_NAMES "${ARG_BUILTIN_NAMES}")
    set(OUTPUT_FILE builtins_list.h)

    set(GENERATE_BUILTIN_TARGET generate-builtin-header-${ARG_BUILTIN_TARGET})
    add_custom_target(${GENERATE_BUILTIN_TARGET}
        WORKING_DIRECTORY ${FILE_LOCATION}/
        COMMAND python ${CMAKE_SOURCE_DIR}/tools/embed_assets.py
            --input-files ${NAMES}
            --output-file ${ARG_BUILTIN_HEADER_FILE_DIR}/${OUTPUT_FILE}
            --filenames ${ARG_BUILTIN_NAMES}
            --variable-names ${VARIABLE_NAMES}
            COMMENT
                "Generating builtin header for target ${ARG_BUILTIN_TARGET}."
        VERBATIM
    )

    add_dependencies(${ARG_BUILTIN_TARGET} ${GENERATE_BUILTIN_TARGET})

endfunction()
