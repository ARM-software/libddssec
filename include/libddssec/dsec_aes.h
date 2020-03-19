/*
 * DDS Security library
 * Copyright (c) 2018-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_aes.h
 * Source code for AES operations.
 */

#ifndef DSEC_AES_H
#define DSEC_AES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * \defgroup GroupAES AES Operation
 * \{
 */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * \brief Encrypt an input buffer and produce the associated tag.
 *
 * \details Encrypts inside the TA and returns the data to the Normal World.
 *
 * \param[out] output_data Output data buffer. Should have a size greater than
 *     or equal to the input buffer.
 *
 * \param[out] output_data_size Size of the output data.
 * \param[out] tag Output buffer for the generated tag.
 * \param[out] tag_size Size of the tag output buffer in bytes (some TA-internal
 *     representations use bits).
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param key_data Buffer containing the key to be used.
 * \param key_data_size Size of the key data.
 * \param data_in Buffer with the data to be processed.
 * \param data_in_size Size of the input data.
 * \param iv The initialization vector (i.e. a buffer).
 * \param iv_size The size of the initialization vector.
 *
 * \retval ::DSEC_SUCCESS Session key has been generated.
 * \return TEE_Result from the function DSEC_TA_CMD_AES_ENCRYPT invoked in the
 *      TA converted to a DSEC_E_
 */
int32_t dsec_aes_encrypt(uint8_t* output_data,
                         uint32_t* output_data_size,
                         uint8_t* tag,
                         uint32_t* tag_size,
                         const struct dsec_instance* instance,
                         uint8_t* key_data,
                         uint32_t key_data_size,
                         uint8_t* data_in,
                         uint32_t data_in_size,
                         uint8_t* iv,
                         uint32_t iv_size);

/*!
 * \brief Decrypt an input buffer.
 *
 * \details Decrypts inside the TA and returns the data to the Normal World.
 *
 * \param[out] output_data Output data buffer.
 * \param[out] output_data_size Size of the output data.
 * \param tag Buffer for the tag.
 * \param tag_size Size of the tag buffer in bytes (some TA-internal
 *     representations use bits).
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param key_data Buffer containing the key to be used.
 * \param key_data_size Size of the key data.
 * \param data_in Buffer with the data to be processed.
 * \param data_in_size Size of the input data.
 * \param iv The initialization vector (i.e. a buffer).
 * \param iv_size The size of the initialization vector.
 *
 * \retval ::DSEC_SUCCESS Session key has been generated.
 * \return TEE_Result from the function DSEC_TA_CMD_SESSION_KEY_ENCRYPT invoked
 *  in the TA converted to a DSEC_E_
 */
int32_t dsec_aes_decrypt(uint8_t* output_data,
                         uint32_t* output_data_size,
                         const struct dsec_instance* instance,
                         uint8_t* tag,
                         uint32_t tag_size,
                         uint8_t* key_data,
                         uint32_t key_data_size,
                         uint8_t* data_in,
                         uint32_t data_in_size,
                         uint8_t* iv,
                         uint32_t iv_size);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_AES_H */
