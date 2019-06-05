#
# DDS Security library
# Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Generates a list of assets and metadata at [builddir]/builtins_list.h specific
# to the Trusted Application.
#
# FILE_PATH <name1;name2;name3> - List of builtin filenames used for:
#   * Name of the header files
#   * Name of the variables in the header files
#   Note: NAMES must not contain special characters or spaces. Any periods in
#   the filename (e.g. 'file.extension') will be converted to underscores (e.g.
#   'file_extension') for the filename and the variable in the header.
function(dsec_embed_asset_files)
    set(OPTIONS)
    set(ONE_VALUE_KEYWORDS TARGET HEADER_FILE_DIR)
    set(MULTI_VALUE_KEYWORDS FILE_PATH)
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

    if(NOT DEFINED ARG_BUILTIN_HEADER_FILE_DIR)
        message(FATAL_ERROR "Builtin objects must have a output directory:
                HEADER_FILE_DIR")
    endif()

    if(NOT DEFINED ARG_BUILTIN_TARGET)
        message(FATAL_ERROR "Builtin objects must have a valid TARGET.")
    endif()

    set(OUTPUT_FILE builtins_list.h)
    set(GENERATE_BUILTIN_TARGET generate-builtin-header-${ARG_BUILTIN_TARGET})

    if(NOT DEFINED ARG_BUILTIN_FILE_PATH)

        add_custom_target(${GENERATE_BUILTIN_TARGET}
            COMMAND ${CMAKE_COMMAND} -E make_directory
                ${CMAKE_CURRENT_BINARY_DIR}/builtins/
            WORKING_DIRECTORY ${FILE_LOCATION}/
            COMMAND python ${DSEC_CMAKE_MODULE_PATH}/../../tools/embed_assets.py
                --output-file ${CMAKE_CURRENT_BINARY_DIR}/builtins/${OUTPUT_FILE}
                empty_builtin
                COMMENT
                    "Generating empty builtin for target ${ARG_BUILTIN_TARGET}."
            VERBATIM
        )

    else()

        foreach(FILE_PATH ${ARG_BUILTIN_FILE_PATH})
            get_filename_component(NAME_FILE ${FILE_PATH} NAME)
            set(NAME_FILES ${NAME_FILES} ${NAME_FILE})
        endforeach()

        string(REPLACE "." "_" VARIABLE_NAMES "${NAME_FILES}")

        add_custom_target(${GENERATE_BUILTIN_TARGET}
            COMMAND ${CMAKE_COMMAND} -E make_directory
                ${CMAKE_CURRENT_BINARY_DIR}/builtins/
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
            COMMAND python ${DSEC_CMAKE_MODULE_PATH}/../../tools/embed_assets.py
                --output-file ${CMAKE_CURRENT_BINARY_DIR}/builtins/${OUTPUT_FILE}
                data_builtin
                    --input-files ${ARG_BUILTIN_FILE_PATH}
                    --filenames ${NAME_FILES}
                    --variable-names ${VARIABLE_NAMES}
                COMMENT
                    "Generating builtin for target ${ARG_BUILTIN_TARGET}."
            VERBATIM
        )

    endif()

    add_dependencies(${ARG_BUILTIN_TARGET} ${GENERATE_BUILTIN_TARGET})

endfunction()
