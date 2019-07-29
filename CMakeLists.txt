#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

cmake_minimum_required(VERSION 3.5)
project("libddssec" VERSION 0.1.0 LANGUAGES C)
set(${PROJECT_NAME}_DESCRIPTION_SUMMARY "libddssec")

set(DSEC_CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules
    CACHE INTERNAL "")

set(CMAKE_MODULE_PATH ${DSEC_CMAKE_MODULE_PATH})

message(STATUS
    "${${PROJECT_NAME}_DESCRIPTION_SUMMARY} version ${PROJECT_VERSION}"
)

option(BUILD_TEST "Build tests" OFF)
option(BUILD_DOC "Build doxygen documentation" OFF)

# Toolchain options
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(COMPILE_OPTIONS
    -Wall
    -Wextra
    -Werror
    -Wno-missing-field-initializers
    -Wno-unused-parameter
    -Wfloat-equal
    -Wformat-security
    -Wformat-nonliteral
    -Wformat-y2k
    -Wmissing-declarations
    -Wmissing-include-dirs
    -Wmissing-noreturn
    -Wnested-externs
    -Wshadow
    -Wstrict-prototypes
    -Wswitch-default
    -pedantic
    -pedantic-errors
    -shared
    -fpic
    -pipe
    -fstack-protector-all
    -fpie
    -Wl,-pie
    -Wl,-z,defs
    -Wl,-z,now
    -Wl,-z,relro
)

#
# Generate version header
#
set(version_header ${CMAKE_CURRENT_BINARY_DIR}/include/dsec_version.h)
message(STATUS "Generating version header in ${version_header}")
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/${PROJECT_NAME}/dsec_version.h.in
    ${version_header}
)

#
# Settings for OP-TEE
#
find_package(OPTEECLIENT REQUIRED)

#
# Source files
#
set(PROJECT_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/trusted_application/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
)

# Files from external libraries which need to be included in the source but
# which don't need to be checked for documentation.
set(EXTERNAL_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set(PROJECT_SOURCE
    src/dsec_ca.c
    src/dsec_ih.c
    src/dsec_ih_ca.c
    src/dsec_ih_cert.c
    src/dsec_ih_privkey.c
    src/dsec_hh.c
    src/dsec_hh_dh.c
    src/dsec_ssh.c
    src/dsec_hh_challenge.c
)

set(DSEC_TA_UUID
    "{0x8ee919be,0x3954,0x4170,{0xb4,0xc2,0xda,0x16,0x9f,0x39,0x53,0x6e}}"
    CACHE INTERNAL "")

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/util_function.cmake)
dsec_get_string_uuid(${DSEC_TA_UUID} DSEC_TA_UUID_STRING)

list(APPEND COMPILE_DEFINITIONS
    -DDSEC_TA_UUID=${DSEC_TA_UUID}
    -DDSEC_TA_UUID_STRING="${DSEC_TA_UUID_STRING}"
)

#
# Trusted Application
#
add_subdirectory(trusted_application)

#
# Test support subdirectory
#
if(BUILD_TEST)
    add_subdirectory(tests)
endif()

#
# Documentation
#
if(BUILD_DOC)
    set(README ${CMAKE_CURRENT_SOURCE_DIR}/readme.md)
    add_subdirectory(doc)
endif()

#
# Library settings
#
add_library(${PROJECT_NAME} SHARED ${PROJECT_SOURCE})

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        OPTEECLIENT::OPTEECLIENT
)

target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${COMPILE_DEFINITIONS})
target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
        ${PROJECT_INCLUDES}
    PRIVATE
        ${EXTERNAL_INCLUDES}
)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/libddssec>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/trusted_application/include>
            $<INSTALL_INTERFACE:include>
        INTERFACE_LINK_LIBRARIES
            ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.so
        LINK_INTERFACE_LANGUAGES
            C
            CXX
        COMPILE_DEFINITIONS
            ${COMPILE_DEFINITIONS}
        COMPILE_OPTIONS
            ${COMPILE_OPTIONS}
        IMPORTED_LINK_INTERFACE_LIBRARIES
            OPTEECLIENT::OPTEECLIENT
        PREFIX
             ""
)

install(
    TARGETS
        ${PROJECT_NAME}
    EXPORT
        ${PROJECT_NAME}
    LIBRARY
        DESTINATION lib
    INCLUDES
        DESTINATION include
    PUBLIC_HEADER
        DESTINATION include
)

# Generates and installs a CMake file containing code to import targets from the
# installation tree into another project. The generated file is
# ${PROJECT_NAME}.cmake (value specified in EXPORT)
install(
    EXPORT
        ${PROJECT_NAME}
    DESTINATION
        lib/cmake/libddssec
    COMPONENT
        OPTEECLIENT::OPTEECLIENT
    EXPORT_LINK_INTERFACE_LIBRARIES
)

export(
    TARGETS
        ${PROJECT_NAME}
    FILE
      "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-targets.cmake"
    EXPORT_LINK_INTERFACE_LIBRARIES
)

add_library(arm::libddssec ALIAS ${PROJECT_NAME})

