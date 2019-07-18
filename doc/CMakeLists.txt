#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Add a target to generate API documentation with Doxygen
find_package(Doxygen)
option(BUILD_DOCUMENTATION
    "Create and install the HTML based API documentation (requires Doxygen)"
    ${DOXYGEN_FOUND}
)

if(BUILD_DOCUMENTATION)
    if(NOT DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen is needed to build the documentation.")
    endif()

    set(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/doxyfile.in)
    set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/doxyfile)

    file(GLOB DOC_IMAGES
        "${CMAKE_CURRENT_SOURCE_DIR}/media/*.svg"
    )

    set(DOC_INCLUDES
        ${PROJECT_INCLUDES}
        ${TEST_INCLUDES}
        ${README}
        ${CMAKE_CURRENT_SOURCE_DIR}/about_libddssec.md
        ${CMAKE_CURRENT_SOURCE_DIR}/how_to_get_fvp_binaries.md
        ${CMAKE_CURRENT_SOURCE_DIR}/using_libddssec.md
    )
    # Space separated list of include directories
    string(REPLACE ";" " " INCLUDES_INPUT "${DOC_INCLUDES}")

    # Generate Doxygen configuration file using template
    configure_file(${doxyfile_in} ${doxyfile})

    add_custom_target(doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
        COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/html/media
        COMMAND cp ${DOC_IMAGES} ${CMAKE_CURRENT_BINARY_DIR}/html/media
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)

    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION share/doc)
endif()
