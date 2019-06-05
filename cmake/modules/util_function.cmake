#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

#
# Convert a UUID to a string UUID
#
# TA_UUID <uuid> - Input TA_UUID (can be generated using `uuidgen`).
# TA_UUID_STRING <uuid_string> - Output string generated.
function(dsec_get_string_uuid TA_UUID TA_UUID_STRING)

    if(NOT DEFINED TA_UUID)
        message(FATAL_ERROR "TA_UUID must be defined")
    endif()


    set(TA_UUID_STRING_TMP "")

    string(REPLACE "{" "" TA_UUID_STRING_TMP ${TA_UUID})
    string(REPLACE "}" "" TA_UUID_STRING_TMP ${TA_UUID_STRING_TMP})
    string(REPLACE "0x" "" TA_UUID_STRING_TMP ${TA_UUID_STRING_TMP})

    string(REGEX MATCH "(.*),(.*),(.*),(.*,.*),(.*,.*,.*,.*,.*,.*)"
           TA_UUID_STRING_TMP
           ${TA_UUID_STRING_TMP})

    if(NOT DEFINED CMAKE_MATCH_1 OR
       NOT DEFINED CMAKE_MATCH_2 OR
       NOT DEFINED CMAKE_MATCH_3 OR
       NOT DEFINED CMAKE_MATCH_4 OR
       NOT DEFINED CMAKE_MATCH_5)

        message(FATAL_ERROR "TA_UUID has a wrong format: ${TA_UUID}")
    endif()

    string(REPLACE "," "" PART1 ${CMAKE_MATCH_1})
    string(REPLACE "," "" PART2 ${CMAKE_MATCH_2})
    string(REPLACE "," "" PART3 ${CMAKE_MATCH_3})
    string(REPLACE "," "" PART4 ${CMAKE_MATCH_4})
    string(REPLACE "," "" PART5 ${CMAKE_MATCH_5})

    string(CONCAT
           TA_UUID_STRING_TMP
           ${PART1} "-" ${PART2} "-" ${PART3} "-" ${PART4} "-" ${PART5}
    )

    set(${TA_UUID_STRING} "${TA_UUID_STRING_TMP}" PARENT_SCOPE)

endfunction()
