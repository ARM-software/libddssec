/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * OP-TEE TA specific for HMAC256
 */

#include <dsec_ta_hmac.h>
#include <mbedtls/md.h>

#define DSEC_HMAC_DATA_SIZE (32U)
#define DSEC_KEY_DATA_SIZE_SMALL (16U)
#define DSEC_KEY_DATA_SIZE_LARGE (32U)

TEE_OperationHandle operation = TEE_HANDLE_NULL;

TEE_Result dsec_ta_hmac_256_init(void)
{
    static bool is_allocated = false;
    TEE_Result result = 0;

    if (!is_allocated) {
        result = TEE_AllocateOperation(&operation,
                                       TEE_ALG_HMAC_SHA256,
                                       TEE_MODE_MAC,
                                       32*8);

        if (result != TEE_SUCCESS) {
            EMSG("Cannot allocate HMAC256 operation.\n");
        }

    } else {
        result = TEE_SUCCESS;
    }

    return result;
}

TEE_Result dsec_ta_hmac_256(uint8_t* hmac_data,
                            uint32_t* hmac_data_size,
                            const uint8_t* key_data,
                            uint32_t key_data_size,
                            const uint8_t* data_in,
                            uint32_t data_in_size)
{
    TEE_Result result = 0;
    mbedtls_md_context_t ctx;
    int mbedtls_result = 0;

    if ((hmac_data != NULL) &&
        (hmac_data_size != NULL) &&
        (*hmac_data_size >= DSEC_HMAC_DATA_SIZE) &&
        (data_in != NULL) &&
        ((key_data_size == DSEC_KEY_DATA_SIZE_SMALL) ||
        (key_data_size == DSEC_KEY_DATA_SIZE_LARGE))) {

            const mbedtls_md_info_t* md_info =
                mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

            if (md_info != NULL) {

                mbedtls_md_init(&ctx);

                mbedtls_result = mbedtls_md_setup(&ctx, md_info, 1);
                if (mbedtls_result == 0) {
                    mbedtls_result =
                        mbedtls_md_hmac_starts(&ctx,
                                               (const unsigned char*)key_data,
                                               key_data_size);

                    if (mbedtls_result == 0) {
                        mbedtls_result =
                            mbedtls_md_hmac_update(&ctx,
                                                   (const unsigned char*)
                                                   data_in,
                                                   data_in_size);

                        if (mbedtls_result == 0) {
                            mbedtls_result =
                                mbedtls_md_hmac_finish(&ctx, hmac_data);

                            if (mbedtls_result == 0) {
                                result = TEE_SUCCESS;
                                *hmac_data_size = DSEC_HMAC_DATA_SIZE;
                            } else {
                                EMSG("Cannot finish the HMAC operation %d.",
                                     mbedtls_result);

                                result = TEE_ERROR_BAD_PARAMETERS;
                            }
                        } else {
                            EMSG("Cannot update the HMAC operation %d.",
                                 mbedtls_result);

                            result = TEE_ERROR_BAD_PARAMETERS;
                        }
                    } else {
                        EMSG("Cannot start the HMAC operation %d.",
                             mbedtls_result);

                        result = TEE_ERROR_BAD_PARAMETERS;
                    }
                } else {
                    EMSG("Cannot setup the HMAC operation %d.",
                         mbedtls_result);

                    result = TEE_ERROR_BAD_STATE;
                }
                mbedtls_md_free(&ctx);
            } else {
                EMSG("Could not get message digest information");
                result = TEE_ERROR_BAD_STATE;
            }
    } else {
        EMSG("Parameters are invalid.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

#if DSEC_TEST
#include <string.h>

TEE_Result dsec_ta_hmac_256_test(uint32_t parameters_type,
                                 const TEE_Param parameters[1])
{
    TEE_Result result = 0;
    uint32_t test_number = 0;
    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        uint8_t hmac_data[32] = {0};
        uint32_t hmac_data_size = 32;

        const uint8_t key_data[] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

        const uint8_t data_in[] = {
            0x30, 0x45, 0x2, 0x21, 0x0, 0x9e, 0x8, 0x6f, 0x20, 0x76, 0x58, 0x1b,
            0x6d, 0xd4, 0xd4, 0xab, 0xfd, 0xbb, 0x97, 0xfa, 0xbb, 0xdd, 0x5,
            0x9f, 0x8d, 0xb6, 0x21, 0x37, 0x86, 0x6d, 0x43, 0x38, 0xad, 0x33,
            0x8b, 0x3b, 0x7d, 0x2, 0x20, 0x20, 0xae, 0x5e, 0xa7, 0x5c, 0x8e,
            0x70, 0xd2, 0xbb, 0x26, 0x47, 0xba, 0x77, 0xa2, 0x2f, 0xaa, 0x10,
            0x12, 0xa8, 0xd7, 0x47, 0x50, 0xb3, 0x80, 0x1f, 0x4b, 0xea, 0x4b,
            0x66, 0x75, 0x4c, 0x27};

        uint32_t data_in_size = sizeof(data_in);

        uint8_t hmac_expected[] = {
            0x52, 0x24, 0xdb, 0xfa, 0x8b, 0x5c, 0x3, 0x23, 0x87, 0xda, 0x40,
            0x4f, 0x84, 0x9f, 0xc8, 0x29, 0xe4, 0x77, 0xc4, 0x64, 0x31, 0x73,
            0xe2, 0x53, 0xea, 0x97, 0xe4, 0x9d, 0x3a, 0xb9, 0xe0, 0xd0};

        test_number = parameters[0].value.a;

        switch (test_number) {
        case 0:
            result = dsec_ta_hmac_256(NULL,
                                      &hmac_data_size,
                                      key_data,
                                      sizeof(key_data),
                                      data_in,
                                      data_in_size);

            if (result == TEE_ERROR_BAD_PARAMETERS) {
                result = TEE_SUCCESS;
            } else {
                EMSG("Unexpected result.\n");
            }

            break;

        case 1:
            result = dsec_ta_hmac_256(hmac_data,
                                      &hmac_data_size,
                                      key_data,
                                      sizeof(key_data),
                                      data_in,
                                      data_in_size);

            if ((result == TEE_SUCCESS) &&
                (hmac_data_size == sizeof(hmac_expected)) &&
                (memcmp(hmac_data, hmac_expected, hmac_data_size) != 0)) {

                EMSG("Expected value does not match.\n");
                result = TEE_ERROR_SECURITY;
            }
            break;

        default:
            EMSG("Test %u not implemented.\n", test_number);
            result = TEE_ERROR_NOT_IMPLEMENTED;
            break;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

#endif /* DSEC_TEST */
