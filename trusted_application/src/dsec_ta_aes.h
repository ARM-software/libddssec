/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DSEC_TA_AES_H
#define DSEC_TA_AES_H

#include <tee_api.h>
#include <stdint.h>

/*! Maximum size of the AES key used for the Operation Handle. */
#define DSEC_TA_AES_MAX_KEY_SIZE (256U)
/*! Size of the tag for the authentication function. */
#define DSEC_TA_AES_MAX_TAG_SIZE (16U)
/*! Size the temporary buffer used for moving data back to the Normal World. */
#define DSEC_TA_AES_STATIC_OUTPUT_SIZE (2<<16)

/*! Initialize the operation handles necessary for the AES operations. */
TEE_Result dsec_ta_aes_init(void);

/*!
 * \brief Encrypt an input buffer and produce the associated tag.
 *
 * \param[out] output_data Output data buffer.
 * \param[out] output_data_size Size of the data in the output data buffer.
 * \param[out] tag Output buffer for for generated tag.
 * \param[out] tag_size Size of the tag to be generated.
 * \param key_data Buffer containing the key to be used.
 * \param key_data_size Size of the Key to be used in bytes.
 * \param data_in Input buffer with the data to be processed.
 * \param data_in_size Size of the input buffer.
 * \param iv Initialization vector.
 * \param iv_size Size of the initialization vector.
 *
 * \retval ::DSEC_SUCCESS
 * \return TEE_ERROR_BAD_PARAMETERS Bad parameters were passed to the TA.
 * \return TEE_* error code from TEE_AEEncryptFinal().
 */
TEE_Result aes_encrypt(uint8_t* output_data,
                       uint32_t* output_data_size,
                       uint8_t* tag,
                       uint32_t* tag_size,
                       const uint8_t* key_data,
                       uint32_t key_data_size,
                       const uint8_t* data_in,
                       uint32_t data_in_size,
                       const uint8_t* iv,
                       uint32_t iv_size);

/*!
 * \brief Decrypt an input buffer.
 *
 * \param[out] output_data Output data buffer.
 * \param[out] output_data_size Size of the data in the output data buffer.
 * \param[out] tag Output buffer for for generated tag.
 * \param[out] tag_size Size of the tag to be generated.
 * \param key_data Buffer containing the key to be used.
 * \param key_data_size Size of the Key to be used in bytes.
 * \param data_in Input buffer with the data to be processed.
 * \param data_in_size Size of the input buffer.
 * \param iv Initialization vector.
 * \param iv_size Size of the initialization vector.
 *
 * \retval ::DSEC_SUCCESS
 * \return TEE_ERROR_BAD_PARAMETERS Bad parameters were passed to the TA.
 * \return TEE_* error code from TEE_AEUpdate().
 */
TEE_Result aes_decrypt(uint8_t* output_data,
                       uint32_t* output_data_size,
                       uint8_t* tag,
                       uint32_t* tag_size,
                       const uint8_t* key_data,
                       uint32_t key_data_size,
                       const uint8_t* data_in,
                       uint32_t data_in_size,
                       const uint8_t* iv,
                       uint32_t iv_size);

/*!
 * \brief Perform AES on a buffer from the Normal World.
 *
 * \brief Encrypt an input buffer and produce the associated tag.
 *     The expected TEE_Params are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *
 * \param [out] parameters[0].memref.buf Output data buffer.
 * \param [out] parameters[0].memref.size Output data buffer size. Should have
 *     a size greater than or equal to the input buffer.
 *
 * \param [out] parameters[1].memref.buf Output tag buffer.
 * \param [out] parameters[1].memref.size Output tag buffer size in bytes.
 * \param  parameters[2].memref.buf Key data buffer.
 * \param  parameters[2].memref.size Key data buffer size.
 * \param  parameters[3].memref.buf Initialization vector.
 * \param  parameters[3].memref.size Initialization vector size.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \retval ::TEE_SUCCESS Input buffer has been hashed and returned.
 * \return TEE_ERROR_BAD_PARAMETERS Bad parameters were passed to the TA.
 * \return TEE_* error code from TEE_AEEncryptFinal().
 *
 */
TEE_Result dsec_ta_aes_encrypt(uint32_t parameters_type,
                               TEE_Param parameters[4]);

/*!
 * \brief Perform AES decryption on a buffer from the Normal World.
 *
 * \brief Encrypt an input buffer and produce the associated tag.
 *     The expected TEE_Params are:
 *        - TEE_PARAM_TYPE_MEMREF_INOUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *
 * \param [in] parameters[0].memref.buf Input data buffer.
 * \param [in] parameters[0].memref.size Input data buffer size.
 * \param [out] parameters[0].memref.buf Output data buffer.
 * \param [out] parameters[0].memref.size Output data buffer size.
 * \param [out] parameters[1].memref.buf Output tag buffer.
 * \param [out] parameters[1].memref.size Output tag buffer size in bytes.
 * \param  parameters[2].memref.buf Key data buffer.
 * \param  parameters[2].memref.size Key data buffer size.
 * \param  parameters[3].memref.buf Initialization vector.
 * \param  parameters[3].memref.size Initialization vector size.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 *
 * \retval ::TEE_SUCCESS Input buffer has been hashed and returned.
 * \return TEE_ERROR_BAD_PARAMETERS Bad parameters were passed to the TA.
 * \return TEE_* error code from TEE_AEEncryptFinal().
 */
TEE_Result dsec_ta_aes_decrypt(uint32_t parameters_type,
                               TEE_Param parameters[4]);

TEE_Result dsec_ta_aes_get_mac(uint32_t parameters_type,
                               TEE_Param parameters[4]);

#endif /* DSEC_TA_AES_H */
