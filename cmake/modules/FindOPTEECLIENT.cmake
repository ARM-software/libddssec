#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

#
# FindOPTEECLIENT
# ---------------
# Find the OP-TEE Client library and header files.
#
# Imported Targets
#
# This module defines target OPTEECLIENT::OPTEECLIENT, if OPTEECLIENT has been
# found.
#
# Result Variables
#
# This module will set the following variables in your project:
#
# OPTEECLIENT_FOUND
#   OP-TEE Client is installed or located at the specified location.
# OPTEECLIENT_LIBRARY
#   The OP-TEE Client library, libteec.so or libteec.a.
# OPTEECLIENT_INCLUDE_DIR
#   The location of OP-TEE Client public header files.
#
# Hints
#
# OP-TEE Client should be installed or specified with the environment variable
# or command-line argument OPTEECLIENT_DIR pointing to the root of the
# directory containing the library and header files. An internal CMake set of
# OPTEECLIENT_DIR will override the environment variable.
#
# If OPTEECLIENT_DIR is specified and the necessary files are not found, the
# second method to find the library won't be checked.

set(OPTEECLIENT_FOUND FALSE)
set(OPTEECLIENT_NAME teec)

if(NOT DEFINED OPTEECLIENT_DIR)
    if(DEFINED ENV{OPTEECLIENT_DIR})
        set(OPTEECLIENT_DIR $ENV{OPTEECLIENT_DIR})
    endif()
endif()

# OP-TEE client can be built with the Makefile or with CMake which gives
# different output folders, both separate from the header files. This searches
# the given folder recursively.
if(DEFINED OPTEECLIENT_DIR)

    message(STATUS "Using OPTEECLIENT_DIR: " ${OPTEECLIENT_DIR})

    # Search for OPTEECLIENT library. Tries to find a shared library first,
    # then tries to find a static library.
    file(GLOB_RECURSE
        OPTEECLIENT_LIBRARY
        "${OPTEECLIENT_DIR}/*/lib${OPTEECLIENT_NAME}.so"
    )
    if(NOT OPTEECLIENT_LIBRARY)
        file(GLOB_RECURSE
            OPTEECLIENT_LIBRARY
            "${OPTEECLIENT_DIR}/*/lib${OPTEECLIENT_NAME}.a"
        )
    endif()

    if(NOT OPTEECLIENT_LIBRARY)
        string(CONCAT FATAL_MSG
            "OP-TEE Client library not found in OPTEECLIENT_DIR: "
            "${OPTEECLIENT_DIR}"
        )
        message(FATAL_ERROR ${FATAL_MSG})
    endif()

    # Only use the first location found
    list(LENGTH OPTEECLIENT_LIBRARY _OPTEECLIENT_LIBRARY_LENGTH)
    if(${_OPTEECLIENT_LIBRARY_LENGTH} GREATER 1)
        string(REPLACE ";" " " LIBRARY_S "${OPTEECLIENT_LIBRARY}")
        string(CONCAT WARNING_MSG
            "Found multiple OP-TEE Client libraries: "
            "${LIBRARY_S}"
        )

        list(GET OPTEECLIENT_LIBRARY 0 OPTEECLIENT_LIBRARY)
        string(CONCAT WARNING_MSG "${WARNING_MSG}\n"
            "Using: ${OPTEECLIENT_LIBRARY}"
        )
        message(WARNING ${WARNING_MSG})
    endif()

    # Search for OPTEECLIENT headers. Finds the client API, then derives the
    # directory. find_path is insufficient and won't check recursively.
    file(GLOB_RECURSE
        OPTEECLIENT_INCLUDE_API
        "${OPTEECLIENT_DIR}/*/tee_client_api.h"
    )

    if(NOT OPTEECLIENT_INCLUDE_API)
        string(CONCAT FATAL_MSG
            "OP-TEE Client headers not found in OPTEECLIENT_DIR: "
            "${OPTEECLIENT_DIR}"
        )
        message(FATAL_ERROR ${FATAL_MSG})
    endif()

    # Only use the first location found
    list(LENGTH OPTEECLIENT_INCLUDE_API _OPTEECLIENT_INCLUDE_API_LENGTH)
    if(${_OPTEECLIENT_INCLUDE_API_LENGTH} GREATER 1)
        string(REPLACE ";" " " INCLUDE_API_S "${OPTEECLIENT_INCLUDE_API}")
        string(CONCAT WARNING_MSG
            "Found multiple OP-TEE Client API header files: "
            "${INCLUDE_API_S}"
        )
        list(GET OPTEECLIENT_INCLUDE_API 0 OPTEECLIENT_INCLUDE_API)
        string(CONCAT WARNING_MSG "${WARNING_MSG}\n"
            "Using: ${OPTEECLIENT_INCLUDE_API}"
        )
        message(WARNING ${WARNING_MSG})
    endif()

    # Derive header file directory
    get_filename_component(OPTEECLIENT_INCLUDE_DIR
        ${OPTEECLIENT_INCLUDE_API}
        DIRECTORY
    )

    if(NOT OPTEECLIENT_INCLUDE_DIR)
        message(FATAL_ERROR
            "OP-TEE Client headers found but directory couldn't be derived"
        )
    endif()

    unset(OPTEECLIENT_INCLUDE_API)

else()
    # Search the system paths for the library if it is not supplied/found
    find_library(OPTEECLIENT_LIBRARY ${OPTEECLIENT_NAME}.so)
    find_path(OPTEECLIENT_INCLUDE_DIR NAMES tee_client_api.h)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    OPTEECLIENT
    FOUND_VAR
        OPTEECLIENT_FOUND
    FAIL_MESSAGE
        "Install OP-TEE client or specify the location with OPTEECLIENT_DIR"
    REQUIRED_VARS
        OPTEECLIENT_LIBRARY
        OPTEECLIENT_INCLUDE_DIR
)

# If the necessary files were found and the Target was not previously configured
if(OPTEECLIENT_FOUND AND NOT TARGET OPTEECLIENT::OPTEECLIENT)
    add_library(OPTEECLIENT::OPTEECLIENT INTERFACE IMPORTED)
    set_target_properties(
        OPTEECLIENT::OPTEECLIENT
        PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${OPTEECLIENT_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES "${OPTEECLIENT_LIBRARY}"
    )
endif()

unset(OPTEECLIENT_NAME)
