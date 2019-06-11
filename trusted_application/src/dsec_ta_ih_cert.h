/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ta_ih_cert.h
 * TA source code for handling Certificates.
 */

#ifndef DSEC_TA_IH_CERT_H
#define DSEC_TA_IH_CERT_H

/*!
 * \addtogroup GroupTA Trusted Application
 * \{
 */

#include <mbedtls/x509_crt.h>
#include <tee_api.h>
#include <stdint.h>
#include <stdbool.h>

/*!
 * \brief Certificate structure.
 */
struct cert_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! mbedTLS structure representing the certificate of a node. */
    mbedtls_x509_crt cert;
};


/*!
 * \brief Load a certificate to an Identity Handle
 *
 * \details Given a string identifier representing the name of the certificate,
 *     load the certificate in memory and return the handle to this
 *     certificate. The certificate is verified against the Certificate
 *     Authority (CA) contained and initialized in the Identity Handle.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[0].value.a Handle ID of the Identity Handle where the
 *     certificate is supposed to be loaded.
 * \param parameters[1].memref.buf Buffer containing the name of the certificate
 *     authority to be retrieved from secure storage.
 * \param parameters[1].memref.size Given size of the buffer shared. The size
 *     must not exceed DSEC_MAX_NAME_LENGTH.
 *
 * \retval ::TEE_SUCCESS Certificate has been loaded.
 * \retval ::TEE_ERROR_BAD_FORMAT Certificate could not be parsed.
 * \retval ::TEE_ERROR_SIGNATURE_INVALID Certificate could not be verified by
 *     the CA.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set or
 *     input buffer is invalid (NULL, size is 0,..) or specified handle ID leads
 *     to an invalid element.
 * \retval ::TEE_ERROR_ITEM_NOT_FOUND Given certificate's name is not found
 *     in the storage.
 */
TEE_Result dsec_ta_ih_cert_load(uint32_t parameters_type,
                                const TEE_Param parameters[2]);

/*!
 * \brief Given a cert_handle structure, clean the certificate.
 *
 * \details Check if the given structure is not NULL and if the certificate is
 *     initialized. Free the mbedTLS structure and mark it as uninitialized.
 *
 * \param cert_handle Pointer to a structure to be cleaned.
 *
 * \retval ::TEE_SUCCESS Structure cert_handle is freed.
 * \retval ::TEE_ERROR_NO_DATA Certificate is not initialized.
 * \retval ::TEE_ERROR_BAD_PARAMETERS cert_handle pointer is NULL.
 */
TEE_Result dsec_ta_ih_cert_free(struct cert_handle_t* cert_handle);

/*!
 * \brief Given an Identity Handle, clean the certificate.
 *
 * \details Check if the given identity handle is valid and call the function
 *     dsec_ta_ih_cert_free.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[0].value.a Identity Handle containing the certificate to be
 *     unloaded.
 *
 * \retval ::TEE_SUCCESS Handle is unloaded.
 * \retval ::TEE_ERROR_NO_DATA Handle has no certificate loaded.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Identity Handle was not initialized or
 *     out-of-bounds or the structure was not initialized.
 */
TEE_Result dsec_ta_ih_cert_unload(uint32_t parameters_type,
                                  const TEE_Param parameters[1]);


/*!
 * \brief Return a PEM formatted string of the certificate in a identity handle.
 *
 * \details Given an index of a identity handle, return the PEM of the
 *     certificate.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].memref.buff Buffer containing the extracted PEM
 *     string and size.
 * \param[out] parameters[0].memref.size Contains the incoming buffer size and
 *     is updated by the new output size.
 *
 * \param parameters_type The types of each of the parameters in parameters[2]
 *     as described above.
 * \param parameters[1].value.a Value containing the index of the identity
 *    handle containing the wanted certificate.
 *
 * \retval ::TEE_SUCCESS if the buffer returned is the PEM string requested.
 * \retval ::TEE_ERROR_BAD_FORMAT if the certificate could not be encoded as PEM
 *     format.
 * \retval ::TEE_ERROR_SHORT_BUFFER if the given buffer is too small.
 * \retval ::TEE_ERROR_BAD_PARAMETERS if the parameter types are not properly
 *     set or if the index is invalid. The buffer returned is NULL and size set
 *     to 0.
 */
TEE_Result dsec_ta_ih_cert_get(uint32_t parameters_type,
                               TEE_Param parameters[2]);

/*!
 * \brief Return a string buffer of the Subject Name of a certificate.
 *
 * \details Given an index of a identity handle, return the Subject Name (SN)
 *     of the certificate loaded.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].memref.buff Buffer containing the extracted SN
 *     string.
 * \param[out] parameters[0].memref.size Contains the incoming buffer size and
 *     is updated with the new output size.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[1].value.a Value containing the index of the Identity
 *     Handle containing an initialized certificate.
 *
 * \retval ::TEE_SUCCESS Buffer returned is the Subject Name requested.
 * \retval ::TEE_ERROR_BAD_FORMAT Subject Name could not be extracted.
 * \retval ::TEE_ERROR_SHORT_BUFFER Given buffer is too small.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly
 *     set or if the index is invalid. The buffer returned has no data and size
 *     set to 0.
 */
TEE_Result dsec_ta_ih_cert_get_sn(uint32_t parameters_type,
                                  TEE_Param parameters[2]);

/*!
 * \brief Return a string buffer of the Signature Algorithm of a certificate.
 *
 * \details Given an index of a identity handle, return the Signature Algorithm
 *     of the certificate loaded.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].memref.buff Buffer containing the extracted
 *     signature algorithm string.
 * \param[out] parameters[0].memref.size Contains the incoming buffer size and
 *     is updated with the new output size.
 *
 * \param parameters_type The types of each of the parameters in parameters[2]
 *     as described above.
 * \param parameters[1].value.a Value containing the index of the Identity
 *    Handle containing an initialized certificate.
 *
 * \retval ::TEE_SUCCESS Buffer returned is the Signature Algorithm.
 * \retval ::TEE_ERROR_BAD_FORMAT Signature Algorithm could not be
 *     extracted.
 * \retval ::TEE_ERROR_SHORT_BUFFER Given buffer is too small.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set or
 *     the index is invalid. The buffer returned has no data and size set to 0.
 */
TEE_Result dsec_ta_ih_cert_get_signature_algorithm(uint32_t parameters_type,
                                                   TEE_Param parameters[2]);

/*!
 * \brief Load a given Certificate to an Identity Handle
 *
 * \details Given an index of a identity handle, load the given certificate if
 *     the IH has nothing initialized. The loaded certificate is checked against
 *     the Certificate Authority contained in the local identity handle
 *     specified.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters[3]
 *     as described above.
 * \param parameters[0].value.a value of the index of the identity handle that
 *     will get the certificate loaded.
 * \param parameters[1].memref.buffer Buffer containing the certificate to be
 *     loaded.
 * \param parameters[1].memref.size Size of the incoming buffer.
 * \param parameters[2].value.a value of the index of the identity handle that
 *     will check the certificate signature.
 *
 * \retval ::TEE_SUCCESS if the buffer returned is the Signature Algorithm.
 * \retval ::TEE_ERROR_BAD_FORMAT if the buffer cannot be parsed.
 * \retval ::TEE_ERROR_SECURITY if the certificate has invalid signature.
 * \retval ::TEE_ERROR_BAD_PARAMETERS if the parameter types are not properly
 *     set or if the index is invalid.
 */
TEE_Result dsec_ta_ih_cert_load_from_buffer(uint32_t parameters_type,
                                            const TEE_Param parameters[3]);

/*!
 * \brief Verify given signature against given buffer and the public key of the
 *     given identity handle.
 *
 * \details Create the hash of the message, and read the signature with the
 *     public key contained by the identity handle specified to see if the
 *     computed signature and the given signature matches.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters[3]
 *     as described above.
 * \param parameters[0].value.a value of the index of the identity handle that
 *     has the public key.
 * \param parameters[1].memref.buffer Buffer to be checked.
 * \param parameters[1].memref.size Size of the incoming buffer.
 * \param parameters[2].memref.buffer Signature buffer to be checked.
 * \param parameters[2].memref.size Size of the incoming signature.
 *
 * \retval ::TEE_SUCCESS Signature is valid.
 * \retval ::TEE_ERROR_BAD_FORMAT Buffer cannot be parsed.
 * \retval ::TEE_ERROR_SECURITY Buffer and signature do not match.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set or
 *     index is invalid.
 */
TEE_Result dsec_ta_ih_cert_signature_verify(uint32_t parameters_type,
                                            const TEE_Param parameters[3]);


/*!
 * \brief Return a string buffer of the Subject Name of a certificate.
 *
 * \details Given a mbedtls_x509_crt, return the Subject Name (SN) of the
 *     certificate loaded.
 *
 * \param[out] output_buffer Buffer containing the extracted SN string.
 * \param[out] output_length Contains the incoming buffer size and is
 *     updated with the new output size.
 *
 * \param cert Pointer to the certificate.
 *
 * \retval ::TEE_SUCCESS Buffer returned is the requested Subject Name.
 * \retval ::TEE_ERROR_BAD_FORMAT Subject Name could not be extracted.
 * \retval ::TEE_ERROR_SHORT_BUFFER Given buffer is too small.
 */
TEE_Result dsec_ta_cert_get_sn(char* output_buffer,
                               size_t* output_length,
                               const mbedtls_x509_crt* cert);

/*!
 * \brief Return a string buffer of the Signature Algorithm of a certificate.
 *
 * \details Given a mbedtls_x509_crt, return the signature algorithm.
 *
 * \param[out] output_buffer Buffer containing the extracted signature algorithm
 * \param[out] output_length Contains the incoming buffer size and is updated
 *     with the new output size.
 *
 * \param cert Pointer to the certificate.
 *
 * \retval ::TEE_SUCCESS Buffer returned is the Signature Algorithm.
 * \retval ::TEE_ERROR_BAD_FORMAT Signature Algorithm could not be extracted.
 * \retval ::TEE_ERROR_SHORT_BUFFER Given buffer is too small.
 */
TEE_Result dsec_ta_cert_get_signature_algorithm(char* output_buffer,
                                                size_t* output_length,
                                                const mbedtls_x509_crt* cert);

/*!
 * \brief Return a string buffer of the hashed Subject Name of a certificate.
 *
 * \details Given a mbedtls_x509_crt, return the hashed Subject Name (SN) of the
 *     loaded certificate.
 *
 * \param[out] parameters[0].memref.buffer Buffer containing the output hash.
 * \param[out] parameters[0].memref.size At invocation, a pointer to the size of
 *     the incoming buffer. When the function finishes, this size is updated to
 *     the new output size.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 *
 * \retval ::TEE_SUCCESS Buffer returned is the hash requested.
 * \retval ::TEE_ERROR_BAD_FORMAT Subject Name could not be extracted or
 *     parameter types are not properly set or index is invalid.
 * \retval ::TEE_ERROR_SHORT_BUFFER if the given buffer is too small.
 */
TEE_Result dsec_ta_ih_cert_get_sha256_sn(uint32_t parameters_type,
                                         TEE_Param parameters[2]);

/*!
 * \brief Return a string buffer of the raw Subject Name of a certificate.
 *
 * \details Given a mbedtls_x509_crt, return the raw Subject Name (SN) of the
 *     certificate loaded.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].memref.buffer Buffer containing the output.
 * \param[out] parameters[0].memref.size Contains the incoming buffer size and
 *     is updated with the new output size.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 *
 * \retval ::TEE_SUCCESS Buffer returned is the data requested.
 * \retval ::TEE_ERROR_BAD_FORMAT Subject Name could not be extracted or
 *     parameter types are not properly set or index is invalid.
 * \retval ::TEE_ERROR_SHORT_BUFFER if the given buffer is too small.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set or
 *     index is invalid.
 */
TEE_Result dsec_ta_ih_cert_get_raw_sn(uint32_t parameters_type,
                                      TEE_Param parameters[2]);

/*!
 * \}
 */

#endif /* DSEC_TA_IH_CERT_H */
