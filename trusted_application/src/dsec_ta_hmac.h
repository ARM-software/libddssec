/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DSEC_TA_HMAC_H
#define DSEC_TA_HMAC_H

#include <tee_api.h>
#include <stdint.h>
#include <stdbool.h>

/*!
 * \brief Initialize the TEE_OperationHandle for HMAC
 *
 * \retval ::TEE_SUCCESS the operation handle has been initialized and
 *       associated functions can be used.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter are not properly set.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY If there is no more space to allocate the
 *     handle.
 */
TEE_Result dsec_ta_hmac_256_init(void);

/*!
 * \brief Perform an HMAC256
 *
 * \details Search for an initialized element and allocate one for an Identity
 *     Handle in the array and return the corresponding ID.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_OUTPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param [out] hmac_data Output buffer containing the HMAC produced.
 * \param [out] hmac_data_size Contains the size of the output buffer. This
 *     value is updated with the new size of the buffer.
 *
 * \param key_data Key data.
 * \param key_data_size Key data size in bytes. Can be 16 or 32.
 * \param data_in Data to be processed.
 * \param data_in_size Size of the data in bytes.
 *
 * \retval ::TEE_SUCCESS HMAC has been successfully computed.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter are not properly set.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY If there is no more space in the array to
 *     store a new handle.
 */
TEE_Result dsec_ta_hmac_256(uint8_t* hmac_data,
                            uint32_t* hmac_data_size,
                            const uint8_t* key_data,
                            uint32_t key_data_size,
                            const uint8_t* data_in,
                            uint32_t data_in_size);

#if DSEC_TEST
/*!
 * \brief Entrypoint for testing the HMAC functionality.
 *
 * \details Takes an integer as input to execute the corresponding test.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters[0].value.a Test number.
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \retval ::TEE_SUCCESS Test passed.
 * \retval ::TEE_ERROR_* if test failed.
 */
TEE_Result dsec_ta_hmac_256_test(uint32_t parameters_type,
                                 const TEE_Param parameters[1]);

#endif /* DSEC_TEST */

#endif /* DSEC_TA_HMAC_H */
