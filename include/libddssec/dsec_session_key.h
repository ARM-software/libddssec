/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_session_key.h
 * Source code for handling Session Key.
 */

#ifndef DSEC_SESSION_KEY_H
#define DSEC_SESSION_KEY_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*! Maximum size of the session key. */
#define DSEC_MAX_SESSION_KEY_SIZE (32U)

/*!
 * \defgroup GroupSessionKey Session Key
 * \{
 */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * \brief Create a session key and return the buffer
 *
 * \param[out] session_key Output buffer that the key will be written to.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param km_handle_id Valid Key Material Handle ID.
 * \param session_id Session ID used for generation of the session key.
 * \param receiver_specific Receiver specific flag to indicate which session
 *     key to generate.
 *
 * \retval ::DSEC_SUCCESS Session key has been generated.
 * \return TEE_Result from the function DSEC_TA_CMD_SESSION_KEY_CREATE_AND_GET
 *     invoked in the TA converted to a DSEC_E_
 */
int32_t dsec_session_key_create_and_get(uint8_t* session_key,
                                        const struct dsec_instance* instance,
                                        int32_t km_handle_id,
                                        uint32_t session_id,
                                        bool receiver_specific);

/*!
 * \brief Create a session key.
 *
 * \param[out] session_key_id Output ID to the handle.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param km_handle_id Valid Key Material Handle ID.
 * \param session_id Session ID used for generation of the session key.
 * \param receiver_specific Receiver specific flag to indicate which session
 *     key to generate.
 *
 * \retval ::DSEC_SUCCESS Session key has been generated.
 * \return TEE_Result from the function DSEC_TA_CMD_SESSION_KEY_CREATE invoked
 *     in the TA converted to a DSEC_E_
 */
int32_t dsec_session_key_create(int32_t* session_key_id,
                                const struct dsec_instance* instance,
                                int32_t km_handle_id,
                                uint32_t session_id,
                                bool receiver_specific);

/*!
 * \brief Unload a session key.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param session_key_id Input ID to the handle.
 *
 * \retval ::DSEC_SUCCESS Session key has been generated.
 * \return TEE_Result from the function DSEC_TA_CMD_SESSION_KEY_DELETE invoked
 *     in the TA converted to a DSEC_E_
 */
int32_t dsec_session_key_unload(const struct dsec_instance* instance,
                                int32_t session_key_id);

/*!
 * \brief Encrypt a given buffer using the session key corresponding to the
 *     given ID.
 *
 * \param[out] output_data Output data buffer containing the encrypted data.
 * \param[out] output_data_size Input size of the output buffer. This value is
 *     updated with the number of bytes written. This should be the same as the
 *     input buffer length.
 * \param[out] tag Output buffer for the generated tag.
 * \param[out] tag_size Number of bytes for the generation of the tag. This
 *     should match the size of the tag buffer.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param session_key_handle_id ID to a valid session key handle.
 * \param key_data_size Number of bytes to be used for the key. Valid numbers
 *     are 16 or 32 bytes.
 * \param data_in Buffer containing the data to be encrypted.
 * \param data_in_size Size of the buffer to be encrypted.
 * \param iv Initialization vector
 * \param iv_size Size of the initialization buffer.
 *
 * \retval ::DSEC_SUCCESS Session key has been generated.
 * \return TEE_Result from the function DSEC_TA_CMD_SESSION_KEY_ENCRYPT invoked
 *      in the TA converted to a DSEC_E_.
 */
int32_t dsec_session_key_encrypt(uint8_t* output_data,
                                 uint32_t* output_data_size,
                                 uint8_t* tag,
                                 uint32_t* tag_size,
                                 const struct dsec_instance* instance,
                                 int32_t session_key_handle_id,
                                 uint32_t key_data_size,
                                 uint8_t* data_in,
                                 uint32_t data_in_size,
                                 uint8_t* iv,
                                 uint32_t iv_size);

/*!
 * \brief Decrypt a given buffer using the session key corresponding to the
 *     given ID.
 *
 * \param[out] output_data Output data buffer containing the decrypted data.
 * \param[out] output_data_size Input size of the output buffer. This value is
 *     updated with the number of bytes written. This should be the same as the
 *     input buffer length.
 *
 * \param tag Input buffer containing the tag to be checked.
 * \param tag_size Size of the input tag buffer.
 * \param instance Initialized instance to access the Trusted Application.
 * \param session_key_handle_id ID to a valid session key handle.
 * \param key_data_size Number of bytes to be used for the key. Valid numbers
 *     are 16 or 32 bytes.
 * \param data_in Buffer containing the data to be decrypted.
 * \param data_in_size Size of the buffer to be decrypted.
 * \param iv Initialization vector
 * \param iv_size Size of the initialization buffer.
 *
 * \retval ::DSEC_SUCCESS Session key has been generated.
 * \return TEE_Result from the function DSEC_TA_CMD_SESSION_KEY_DECRYPT invoked
 *      in the TA converted to a DSEC_E_
 */
int32_t dsec_session_key_decrypt(uint8_t* output_data,
                                 uint32_t* output_data_size,
                                 const struct dsec_instance* instance,
                                 uint8_t* tag,
                                 uint32_t tag_size,
                                 int32_t session_key_handle_id,
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

#endif /* DSEC_SESSION_KEY_H */
