/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_key_material.h
 * Source code for handling shared secrets.
 */

#ifndef DSEC_KEY_MATERIAL_H
#define DSEC_KEY_MATERIAL_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * \defgroup GroupKeyMaterial Key material
 * \{
 */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * \brief Create key material
 *
 * \details Calls the Trusted Application to create Key Material by setting its
 *     transformation type, filling random values for master_salt and
 *     master_sender_key, creating a unique ID for sender_key_id, setting
 *     receiver_specific_key_id to 0 and master_receiver_specific_key to 0.
 *
 * \param[out] km_handle_id Handle ID of the key material.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param use_gcm Specify to use GCM for authentication instead of GMAC.
 * \param use_256_bits Specify to use 256 bits (32 bytes) instead of 128 bits
 *     (16 bytes).
 *
 * \retval ::DSEC_SUCCESS Key Material has been generated.
 * \retval ::DSEC_E_PARAM Given pointer is NULL.
 * \return TEE_Result from the function DSEC_TA_CMD_KM_CREATE invoked in the TA
 *     converted to a DSEC_E_
 */
int32_t dsec_key_material_create(int32_t* km_handle_id,
                                 const struct dsec_instance* instance,
                                 bool use_gcm,
                                 bool use_256_bits);

/*!
 * \brief Generate key material
 *
 * \details Calls the Trusted Application to generate Key Material. Keys are
 *     created following the OMG specification using the Shared Secret Handle
 *     containing challenge 1, challenge 2 and shared secret.
 *
 * \param[out] out_km_handle_id Handle ID of the key material.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param ssh_id ID to a valid Shared Secret Handle.
 *
 * \retval ::DSEC_SUCCESS Key Material has been generated.
 * \retval ::DSEC_E_PARAM Given pointer is NULL.
 * \return TEE_Result from the function DSEC_TA_CMD_KM_GENERATE invoked in the
 *     TA converted to a DSEC_E_
 */
int32_t dsec_key_material_generate(int32_t* out_km_handle_id,
                                   const struct dsec_instance* instance,
                                   int32_t ssh_id);

/*!
 * \brief Get the data stored by key material
 *
 * \details Calls the Trusted Application to get the data from key material
 *     handle. The given buffers must have the appropriate size to get the
 *     values.
 *
 * Note: the following outputs follow the OMG specification for the key material
 *     structure. Please look at the documentation for more details. The same
 *     names have been used.
 * \param[out] transformation_kind
 * \param[out] master_salt
 * \param[out] sender_key_id
 * \param[out] master_sender_key
 * \param[out] receiver_specific_key_id
 * \param[out] master_receiver_specific_key
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param km_handle Handle ID of the key material handle.
 *
 * \retval ::DSEC_SUCCESS Data has been returned.
 * \retval ::DSEC_E_PARAM Parameter types are not properly set or identifier
 *     specified leads to an invalid handle.
 * \retval ::DSEC_E_DATA At least one requested field is not initialized.
 * \retval ::DSEC_E_SHORT_BUFFER One of the buffer is not big enough.
 */
int32_t dsec_key_material_return(uint8_t transformation_kind[4],
                                 uint8_t master_salt[32],
                                 uint8_t sender_key_id[4],
                                 uint8_t master_sender_key[32],
                                 uint8_t receiver_specific_key_id[4],
                                 uint8_t master_receiver_specific_key[32],
                                 const struct dsec_instance* instance,
                                 int32_t km_handle);

/*!
 * \brief Copy Key Material
 *
 * \details Calls the Trusted Application to create Key Material using the
 *     given material handle. All the fields are copied. Note: if there is no
 *     authentication, receiver_specific_key_id and master_receiver_specific_key
 *     are set to 0.
 *
 * \param[out] out_km_handle_id Handle ID of the key material created from the
 *     copy.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param in_km_handle_id Handle ID of the key material to be copied
 *
 * \retval ::DSEC_SUCCESS Key Material has been copied.
 * \return TEE_Result from the function DSEC_TA_CMD_KM_COPY invoked in the TA
 *     converted to a DSEC_E_
 */
int32_t dsec_key_material_copy(int32_t* out_km_handle_id,
                               const struct dsec_instance* instance,
                               int32_t in_km_handle_id);

/*!
 * \brief Register key material
 *
 * \details Calls the Trusted Application to create Key Material using the
 *     same transformation_kind, master_salt, master_sender_key and
 *     sender_key_id of the input Key Material. However, in case authentication
 *     is used, receiver_specific_key_id, master_receiver_specific_key are
 *     generated or copied.
 *
 * \param[out] out_km_handle_id Handle ID of the key material.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param km_handle_id Handle ID to a valid Key Material.
 * \param is_origin_auth Specify to use authentication.
 * \param generate_receiver_specific_key Specify the generation of the receiver
 *     specific key field.
 *
 * \retval ::DSEC_SUCCESS Key Material has been generated.
 * \retval ::DSEC_E_PARAM Given pointer is NULL.
 * \return TEE_Result from the function DSEC_TA_CMD_KM_REGISTER invoked in the
 *     TA converted to a DSEC_E_
 */
int32_t dsec_key_material_register(int32_t* out_km_handle_id,
                                   const struct dsec_instance* instance,
                                   int32_t km_handle_id,
                                   bool is_origin_auth,
                                   bool generate_receiver_specific_key);

/*!
 * \brief Remove data associated to key material handle.
 *
 * \details Calls the Trusted Application to remove the data from key material
 *     handle.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param km_handle_id Handle ID of the key material handle.
 *
 * \retval ::DSEC_SUCCESS Data has been returned.
 * \retval ::DSEC_E_PARAM Parameter types are not properly set.
 * \retval ::DSEC_E_DATA  Identifier specified leads to an invalid handle.
 */
int32_t dsec_key_material_delete(const struct dsec_instance* instance,
                                 int32_t km_handle_id);
/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_KEY_MATERIAL_H */
