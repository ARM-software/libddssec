#
# DDS Security library
# Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

cmake_minimum_required(VERSION 3.5)
project("libddssec" VERSION 0.1.0 LANGUAGES C)
set(${PROJECT_NAME}_DESCRIPTION_SUMMARY "DDS Security library")

message(STATUS "${${PROJECT_NAME}_DESCRIPTION_SUMMARY} version ${PROJECT_VERSION}")

# Toolchain options
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_C_STANDARD 11)
set (COMPILE_OPTIONS -Wall -Wextra -Werror -Wno-missing-field-initializers -Wno-unused-parameter)

#
# Backend selection
#
set(BACKEND_OPTIONS "openssl" "optee")
set(BACKEND_DEFAULT "openssl")
set(BACKEND ${BACKEND_DEFAULT} CACHE STRING "Select backend (${BACKEND_OPTIONS}, default:${BACKEND_DEFAULT})")
set_property(CACHE BACKEND PROPERTY STRINGS ${BACKEND_OPTIONS})

if(NOT ${BACKEND} IN_LIST BACKEND_OPTIONS)
    message(FATAL_ERROR "Invalid BACKEND. Valid options are: ${BACKEND_OPTIONS}")
endif()

message(STATUS "Backend selected: ${BACKEND}")

#
# Common settings for all backends
#
set(INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/${PROJECT_NAME})
set(PROJECT_SOURCE "")

#
# Backend specific settings
#
if(${BACKEND} STREQUAL "openssl")
    find_package(OpenSSL REQUIRED)
    list(APPEND INCLUDES ${OPENSSL_INCLUDE_DIR})
    add_definitions(-DHAS_OPENSSL)
else()
    message(FATAL_ERROR "${BACKEND} is currently not supported")
endif()

#
# Library settings
#
add_library(${PROJECT_NAME} SHARED ${PROJECT_SOURCE})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDES})