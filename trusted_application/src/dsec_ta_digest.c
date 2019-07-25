/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_ta_digest.h>
#include <mbedtls/md.h>

int32_t dsec_ta_digest_sha256(uint8_t* output,
                      const uint8_t* input,
                      size_t input_size)
{
    int32_t result = DSEC_SUCCESS;
    int mbed_result = 0;
    const mbedtls_md_info_t* md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md_info != NULL) {
        mbed_result = mbedtls_md(md_info, input, input_size, output);

        if (mbed_result == 0) {
            result = DSEC_SUCCESS;
        } else {
            EMSG("Failed to perform digest. Error 0x%x", mbed_result);
            result = DSEC_E_DATA;
        }
    } else {
        EMSG("Failed to get digest information");
        result = DSEC_E_DATA;
    }

    return result;
}

#if DSEC_TEST
TEE_Result dsec_ta_test_sha256(uint32_t parameters_type,
                               TEE_Param parameters[2])
{
    TEE_Result result = TEE_SUCCESS;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        uint8_t output[DSEC_TA_SHA256_SIZE] = {0};
        int32_t dsec_result = dsec_ta_digest_sha256(output,
                                                    parameters[1].memref.buffer,
                                                    DSEC_TA_SHA256_SIZE);

        if (dsec_result == DSEC_SUCCESS) {
            TEE_MemMove(parameters[0].memref.buffer,
                        output,
                        DSEC_TA_SHA256_SIZE);

            parameters[0].memref.size = DSEC_TA_SHA256_SIZE;
            result = TEE_SUCCESS;
        } else {
            EMSG("Could not perform digest. Error: %d", dsec_result);
            result = TEE_ERROR_BAD_STATE;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
#endif /* DSEC_TEST */
