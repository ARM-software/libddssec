#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Convert an UUID string from its canonical textual representation into a
# C-structure string representation. Example:
#  input: "ccb8ddbd-6884-4b65-bb21-db6177153858"
#  output: {0xccb8ddbd,0x6884,0x4b65,{0xbb,0x21,0xdb,0x61,0x77,0x15,0x38,0x58}}
function(dsec_get_uuid_structure UUID RESULT_VARIABLE_NAME)

    if(NOT DEFINED UUID OR NOT DEFINED RESULT_VARIABLE_NAME)
        message(FATAL_ERROR "UUID and RESULT_VARIABLE_NAME must be defined")
    endif()

    set(UUID_TMP ${UUID})
    string(REGEX MATCH "(.*)-(.*)-(.*)-(.*)-(.*)" UUID_TMP ${UUID_TMP})
    if(NOT DEFINED CMAKE_MATCH_1 OR
       NOT DEFINED CMAKE_MATCH_2 OR
       NOT DEFINED CMAKE_MATCH_3 OR
       NOT DEFINED CMAKE_MATCH_4 OR
       NOT DEFINED CMAKE_MATCH_5)

        message(FATAL_ERROR "UUID has a wrong format: ${UUID}")
    endif()

    string(CONCAT UUID_TIME_LOW "0x" ${CMAKE_MATCH_1})
    string(CONCAT UUID_TIME_MID "0x" ${CMAKE_MATCH_2})
    string(CONCAT UUID_TIME_HIGH_AND_VERSION "0x" ${CMAKE_MATCH_3})
    string(CONCAT UUID_CLOCK_AND_NODE ${CMAKE_MATCH_4} ${CMAKE_MATCH_5})

    string(REGEX MATCH
           "(..)(..)(..)(..)(..)(..)(..)(..)"
           UUID_CLOCK_AND_NODE
           ${UUID_CLOCK_AND_NODE})

    if(NOT DEFINED CMAKE_MATCH_1 OR
       NOT DEFINED CMAKE_MATCH_2 OR
       NOT DEFINED CMAKE_MATCH_3 OR
       NOT DEFINED CMAKE_MATCH_4 OR
       NOT DEFINED CMAKE_MATCH_5 OR
       NOT DEFINED CMAKE_MATCH_6 OR
       NOT DEFINED CMAKE_MATCH_7 OR
       NOT DEFINED CMAKE_MATCH_8)

        message(FATAL_ERROR "UUID has a wrong format: ${UUID}")
    endif()

    string(CONCAT
           UUID_CLOCK_AND_NODE
           "0x" ${CMAKE_MATCH_1} ","
           "0x" ${CMAKE_MATCH_2} ","
           "0x" ${CMAKE_MATCH_3} ","
           "0x" ${CMAKE_MATCH_4} ","
           "0x" ${CMAKE_MATCH_5} ","
           "0x" ${CMAKE_MATCH_6} ","
           "0x" ${CMAKE_MATCH_7} ","
           "0x" ${CMAKE_MATCH_8}
    )

    string(CONCAT
           UUID_TEE_STRUCTURE
           "{" ${UUID_TIME_LOW} ","
               ${UUID_TIME_MID} ","
               ${UUID_TIME_HIGH_AND_VERSION} ","
               "{" ${UUID_CLOCK_AND_NODE} "}}"
    )

    set(${RESULT_VARIABLE_NAME} ${UUID_TEE_STRUCTURE} PARENT_SCOPE)

endfunction()
