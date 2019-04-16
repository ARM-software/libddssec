/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ta_ih_ca.h
 * TA source code for handling the identity of a specific node.
 */

#ifndef DSEC_TA_IH_CA_H
#define DSEC_TA_IH_CA_H

#include <mbedtls/x509_crt.h>
#include <tee_api.h>
#include <stdint.h>
#include <stdbool.h>

/*!
 * \brief Certificate Authority (CA) structure.
 */
struct ca_handle_t {
    /*! Initialized field if the structure has been set. */
    bool initialized;
    /*! mbedTLS structure representing the certificate of the CA. */
    mbedtls_x509_crt cert;
};

/*!
 * \brief Load a Certificate Authority (CA) certificate to an Identity Handle
 *
 * \details Given a string identifier representing the name of the Certificate
 *     Authority, load the certificate in memory and return the handle to this
 *     certificate.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters[2]
 *     as specified above.
 * \param parameters[0].value.a Handle ID of the Identity Handle where the CA is
 *     supposed to be loaded.
 * \param parameters[1].memref.buf Buffer containing the name of the certificate
 *     authority to be retrieved from secure storage.
 * \param parameters[1].memref.size Given size of the buffer shared. The size
 *     must not exceed DSEC_MAX_NAME_LENGTH.
 *
 * \retval ::TEE_SUCCESS if the CA has been loaded and the handle returned is
 *     valid.
 * \retval ::TEE_ERROR_BAD_PARAMETERS if the parameter types are not properly
 *     set or if the input buffer is invalid (NULL, size is 0,..) or if the
 *     handle specified leads to an invalid element.
 * \retval ::TEE_ERROR_ITEM_NOT_FOUND if the given CA name is not found in the
 *     storage.
 */
TEE_Result dsec_ta_ih_ca_load(uint32_t parameters_type,
                              const TEE_Param parameters[2]);

/*!
 * \brief Given a ca_handle_t structure, clean the Certificate Authority (CA).
 *
 * \details Check if the given structure is not NULL and if the CA is
 *     initialized. Free the mbedTLS structure and mark it as uninitialized.
 *
 * \param ca_h Pointer to a Certificate Authority handle structure to be
 *     cleaned.
 *
 * \retval ::TEE_SUCCESS ca_h given is freed.
 * \retval ::TEE_ERROR_NO_DATA Certificate Authority is not initialized.
 * \retval ::TEE_ERROR_BAD_PARAMETERS ca_h pointer is NULL.
 */
TEE_Result dsec_ta_ih_ca_free(struct ca_handle_t* ca_h);

/*!
 * \brief Given an Identity Handle, clean the Certificate Authority (CA)
 *     structure.
 *
 * \details Check if the given parameters are valid and call the function
 *     dsec_ta_ih_cert_free to free the CA.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VARIABLE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     specified above.
 * \param parameters[0].value.a Identity Handle containing the CA to unload.
 *
 * \retval ::TEE_SUCCESS if the handle is unloaded.
 * \retval ::TEE_ERROR_BAD_PARAMETERS if the Identity Handle was not initialized
 *     or out of bound or the CA structure was not initialized.
 */
TEE_Result dsec_ta_ih_ca_unload(uint32_t parameters_type,
                                const TEE_Param parameters[1]);

#endif /* DSEC_TA_IH_CA_H */
