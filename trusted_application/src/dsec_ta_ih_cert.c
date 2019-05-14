/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_ih_cert.h>
#include <dsec_ta_ih.h>
#include <dsec_ta_manage_object.h>

/* Load and verify a certificate contained in the given buffer */
static int cert_parse_and_verify(mbedtls_x509_crt* cert,
                                 struct identity_handle_t* ih,
                                 const void* object_buffer,
                                 size_t object_size)
{
    int result_mbedtls = 0;
    TEE_Result result = 0;
    mbedtls_x509_crt* ca = NULL;
    mbedtls_x509_crl* cacrl = NULL;
    uint32_t verification_flags = 0;

    if ((cert != NULL) && (ih != NULL) && (object_buffer != NULL)) {
        mbedtls_x509_crt_init(cert);
        result_mbedtls =
            mbedtls_x509_crt_parse(cert, object_buffer, object_size);

        if (result_mbedtls == 0) {
            ca = &(ih->ca_handle.cert);
            result_mbedtls = mbedtls_x509_crt_verify(cert,
                                                     ca,
                                                     cacrl,
                                                     NULL /* cn */,
                                                     &verification_flags,
                                                     NULL /* f_vrfy */,
                                                     NULL /* p_vrfy */);

            if (result_mbedtls == 0) {
                result = TEE_SUCCESS;
            } else {
                mbedtls_x509_crt_init(cert);
                EMSG("Could not verify the certificate. Error: 0x%x.\n",
                     result_mbedtls);

                result = TEE_ERROR_SECURITY;
            }

        } else {
            EMSG("Could not parse buffer. Error: 0x%x.\n", result_mbedtls);
            result = TEE_ERROR_BAD_FORMAT;
        }
    } else {
        EMSG("Parameters are NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_load(uint32_t parameters_type,
                                const TEE_Param parameters[2])
{
    TEE_Result result = TEE_SUCCESS;

    int32_t index_ih = 0;
    struct identity_handle_t* ih = NULL;
    uint32_t filename_size = 0;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_MEMREF_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_ih = (int32_t)parameters[0].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        /*
         * The Certificate Authority must be initialized as the certificate
         * will be verified against it.
         */
        if ((ih != NULL) &&
            !ih->cert_handle.initialized &&
            ih->ca_handle.initialized) {

            /* Get the certificate name from the input parameters */
            filename_size = (uint32_t)parameters[1].memref.size;
            if (filename_size <= DSEC_MAX_NAME_LENGTH) {
                /* Get the object index to retrieve the buffer */
                void* object_buffer = NULL;
                size_t object_size = 0;

                result = dsec_ta_load_builtin(&object_buffer,
                                              &object_size,
                                              parameters[1].memref.buffer);

                if (result == TEE_SUCCESS) {
                    result = cert_parse_and_verify(&(ih->cert_handle.cert),
                                                   ih,
                                                   object_buffer,
                                                   object_size);

                    if (result == 0) {
                        ih->cert_handle.initialized = true;
                    } else {
                        ih->cert_handle.initialized = false;
                    }

                    dsec_ta_unload_object_memory();
                }

            } else {
                EMSG("Filename is invalid\n");
                result = TEE_ERROR_BAD_PARAMETERS;
            }

        } else {
            EMSG("Identity Handle is not initialized properly\n");
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_free(struct cert_handle_t* cert_h)
{
    TEE_Result result = 0;

    if (cert_h != NULL) {
        if (cert_h->initialized) {
            mbedtls_x509_crt_free(&(cert_h->cert));
            cert_h->initialized = false;
            result = TEE_SUCCESS;
        } else {
            EMSG("Given element has no certificate initialized.\n");
            result = TEE_ERROR_NO_DATA;
        }

    } else {
        EMSG("Pointer to structure cert_handle is NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_unload(uint32_t parameters_type,
                                  const TEE_Param parameters[1])
{
    TEE_Result result = 0;
    int32_t index_ih = 0;
    struct identity_handle_t* ih = NULL;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_ih = (int32_t)parameters[0].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        if (ih != NULL) {
            result = dsec_ta_ih_cert_free(&(ih->cert_handle));
        } else {
            EMSG("Pointer to Identity Handle is NULL.\n");
            result = TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

