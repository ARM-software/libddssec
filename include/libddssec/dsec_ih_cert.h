/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DSEC_IH_CERT_H
#define DSEC_IH_CERT_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * \addtogroup GroupIdentityHandle
 *
 * Function for managing a Certificate inside an Identity Handle.
 * \{
 */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * \brief Maximum size of a filename to describe a path to a Certificate.
 */
#define DSEC_IH_CERT_MAX_FILENAME (2048UL)

/*
 * Extra care is taken here to make sure the maximum size of the filename
 * cannot exceed UINT32_MAX. This is because OPTEE-OS parameters are uint32_t.
 */
#if (DSEC_IH_CERT_MAX_FILENAME > UINT32_MAX)
#error "DSEC_IH_CERT_MAX_FILENAME cannot be more than UINT32_MAX"
#endif

/*!
 * \brief Load a Certificate from a file name.
 *
 * \details Calls the Trusted Application to load a Certificate for a specific
 *     Identity Handle ID.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param ih_id Handle ID of the Identity Handle.
 * \param filename Byte array NULL terminated containing the file name.
 *
 * \retval ::DSEC_SUCCESS if the certificate has been loaded.
 * \return TEE_Result from the function DSEC_TA_CMD_IH_CERT_LOAD invoked in the
 *     TA converted to a DSEC_E_
 */
int32_t dsec_ih_cert_load(const struct dsec_instance* instance,
                          int32_t ih_id,
                          const char* filename);

/*!
 * \brief Unload a Certificate of a Identity Handle.
 *
 * \details Calls the Trusted Application to unload a Certificate for a specific
 *     Identity Handle ID.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param ih_id Handle ID of the Identity Handle.
 *
 * \retval ::DSEC_SUCCESS if the Certificate has been unloaded.
 * \return TEE_Result from the function DSEC_TA_CMD_IH_CERT_UNLOAD invoked in
 *     the TA converted to a DSEC_E_
 */
int32_t dsec_ih_cert_unload(const struct dsec_instance* instance,
                            int32_t ih_id);

/*!
 * \brief Get a Certificate from an Identity Handle.
 *
 * \details Calls the Trusted Application to get a Certificate for a specific
 *     Identity Handle ID.
 *
 * \param[out] output Byte array that will receive the data.
 * \param[out] output_size Pointer to the size of the incoming buffer. This
 *     value will be updated with the number of bytes written to the array.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param ih_id Handle ID of the Identity Handle.
 *
 * \retval ::DSEC_SUCCESS Certificate has been copied to the buffer.
 * \retval TEE_Result from the function DSEC_TA_CMD_IH_CERT_GET invoked in the
 *     TA converted to a DSEC_E_
 */
int32_t dsec_ih_cert_get(uint8_t* output,
                         uint32_t* output_size,
                         const struct dsec_instance* instance,
                         int32_t ih_id);

/*!
 * \brief Get the Subject Name of a Certificate initialized in an Identity
 *     Handle.
 *
 * \details Calls the Trusted Application to extract the Subject Name of a
 *     Certificate from a specific Identity Handle ID.
 *
 * \param[out] output Byte array that will receive the data.
 * \param[out] output_size Pointer to the size of the incoming buffer. This
 *     value will be updated with the number of bytes written to the array.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param ih_id Handle ID of the Identity Handle.
 *
 * \retval ::DSEC_SUCCESS Subject Name has been copied to the buffer.
 * \retval TEE_Result from the function DSEC_TA_CMD_IH_CERT_GET_SN invoked in
 *     the TA converted to a DSEC_E_
 */
int32_t dsec_ih_cert_get_sn(uint8_t* output,
                            uint32_t* output_size,
                            const struct dsec_instance* instance,
                            int32_t ih_id);

/*!
 * \brief Get the Subject Name of a Certificate initialized in an Identity
 *     Handle.
 *
 * \details Calls the Trusted Application to extract the Signature Algorithm of
 *     a certificate from a specific Identity Handle ID.
 *
 * \param[out] output Byte array that will receive the data.
 * \param[out] output_size pointer to the size of the incoming buffer. This
 *     value will be updated with the number of bytes written to the array.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param ih_id Handle ID of the Identity Handle.
 *
 * \retval ::DSEC_SUCCESS Signature Algorithm has been copied to the buffer.
 * \retval TEE_Result from the function
 *     DSEC_TA_CMD_IH_CERT_GET_SIGNATURE_ALGORITHM invoked in the TA converted
 *     to a DSEC_E_
 */
int32_t dsec_ih_cert_get_signature_algorithm(
    uint8_t* output,
    uint32_t* output_size,
    const struct dsec_instance* instance,
    int32_t ih_id);

/*!
 * \brief Load a Certificate from a buffer.
 *
 * \details Calls the Trusted Application to load a Certificate for a specific
 *     Identity Handle ID. The Certificate will be checked against another
 *     identity handle Certificate Authority.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param rih_id Handle ID of the remote identity handle that will have the
 *     loaded certificate.
 * \param input_buffer buffer containing the certificate to be loaded.
 * \param input_size size in byte of the specified buffer.
 * \param lih_id Handle ID of the local identity handle that will check the
 *     input certificate.
 *
 * \retval ::DSEC_SUCCESS if the certificate has been loaded.
 * \retval TEE_Result from the function DSEC_TA_CMD_IH_CERT_LOAD_FROM_BUFFER
 *     invoked in the TA converted to a DSEC_E_
 */
int32_t dsec_ih_cert_load_from_buffer(const struct dsec_instance* instance,
                                      int32_t rih_id,
                                      const uint8_t* input_buffer,
                                      uint32_t input_size,
                                      int32_t lih_id);

/*!
 * \brief Verify a buffer signature using a Public Key from an Identity Handle.
 *
 * \details Calls the Trusted Application to verify if a given signature matches
 *     the buffer signature using the public key of a remote identity handle.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param rih_id Handle ID of the remote identity handle that will check the
 *     signature.
 * \param input_buffer buffer containing the message to be verified.
 * \param input_size size in byte of the specified buffer.
 * \param signature signature of the buffer to be verified
 * \param signature_size sze in byte of the signature buffer.
 *
 * \retval ::DSEC_SUCCESS if the certificate has been loaded.
 * \return TEE_Result from the function DSEC_TA_CMD_IH_CERT_VERIFY invoked in
 *     the TA converted to a DSEC_E_
 */
int32_t dsec_ih_cert_verify(const struct dsec_instance* instance,
                            int32_t rih_id,
                            const void* input_buffer,
                            uint32_t input_size,
                            const void* signature,
                            uint32_t signature_size);

/*!
 * \brief Get the hash Subject Name of a Certificate initialized in an Identity
 *     Handle.
 *
 * \details Calls the Trusted Application to extract the hash Subject Name of a
 *     Certificate from a specific Identity Handle ID.
 *
 * \param[out] output Buffer that will receive the data.
 * \param[out] output_size Pointer to the size of the incoming buffer. This
 *     value will be updated with the number of bytes written to the array.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param ih_id Handle ID of the Identity Handle.
 *
 * \retval ::DSEC_SUCCESS The hash has been copied to the buffer.
 * \return TEE_Result from the function DSEC_TA_CMD_IH_CERT_GET_SN invoked in
 *     the TA converted to a DSEC_E_
 */
int32_t dsec_ih_cert_get_sha256_sn(uint8_t* output,
                                   uint32_t* output_size,
                                   const struct dsec_instance* instance,
                                   int32_t ih_id);

/*!
 * \brief Get the raw Subject Name of a Certificate initialized in an Identity
 *     Handle.
 *
 * \details Calls the Trusted Application to extract the raw Subject Name of a
 *     Certificate from a specific Identity Handle ID.
 *
 * \param[out] output Byte array that will receive the data.
 * \param[out] output_size Pointer to the size of the incoming buffer. This
 *     value will be updated with the number of bytes written to the array.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param ih_id Handle ID of the Identity Handle.
 *
 * \retval ::DSEC_SUCCESS The raw data has been copied to the buffer.
 * \return TEE_Result from the function DSEC_TA_CMD_IH_CERT_GET_RAW_SN invoked
 *     in the TA converted to a DSEC_E_
 */
int32_t dsec_ih_cert_get_raw_sn(uint8_t* output,
                                uint32_t* output_size,
                                const struct dsec_instance* instance,
                                int32_t ih_id);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_IH_CERT_H */
