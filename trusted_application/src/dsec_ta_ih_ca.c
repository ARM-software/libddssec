/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_ih_ca.h>
#include <dsec_ta_ih_cert.h>
#include <dsec_ta_ih.h>
#include <dsec_ta_manage_object.h>

/*
 * Fills the ca_handle_t structure if the given buffer can be properly parsed.
 */
static TEE_Result ca_load_buffer(struct ca_handle_t* ca_handle,
                                 const uint8_t* buffer,
                                 size_t size)
{
    TEE_Result result = TEE_SUCCESS;
    int result_mbedtls = 0;
    mbedtls_x509_crt* cert_chain = NULL;

    if ((ca_handle != NULL) && (buffer != NULL)) {
        /* Setup the mbedtls structure */
        cert_chain = &(ca_handle->cert);
        mbedtls_x509_crt_init(cert_chain);

        /* Load buffer into cert_chain. */
        result_mbedtls = mbedtls_x509_crt_parse(cert_chain, buffer, size);

        if (result_mbedtls == 0) {
            bool is_valid_ca = (cert_chain->ca_istrue == 1);

            if (is_valid_ca) {
                ca_handle->initialized = true;
                result = TEE_SUCCESS;
            } else {
                EMSG("Invalid Certificate Authority certificate.\n");
                ca_handle->initialized = false;
                /*
                 * If an error occurred, make sure to leave the structure in a
                 * correct state.
                 */
                mbedtls_x509_crt_free(cert_chain);
                result = TEE_ERROR_BAD_FORMAT;
            }
        } else {
            EMSG("Could not parse buffer. Error: 0x%x.\n", result_mbedtls);
            ca_handle->initialized = false;
            result = TEE_ERROR_BAD_FORMAT;
        }
    } else {
        EMSG("Parameters are NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_ca_load(uint32_t parameters_type,
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
        if ((ih != NULL) && !ih->ca_handle.initialized) {
            /* Get the certificate name from the input parameters. */
            filename_size = (uint32_t)parameters[1].memref.size;
            if (filename_size <= DSEC_MAX_NAME_LENGTH) {
                /* Get the object index to retrieve the buffer. */
                void* object_buffer = NULL;
                size_t object_size = 0;

                result = dsec_ta_load_builtin(&object_buffer,
                                              &object_size,
                                              parameters[1].memref.buffer);

                if (result == TEE_SUCCESS) {
                    result = ca_load_buffer(&(ih->ca_handle),
                                            object_buffer,
                                            object_size);

                    dsec_ta_unload_object_memory();

                } else {
                    EMSG("Could not load the object.\n");
                    /* Return the value from the function that failed. */
                }
            } else {
                EMSG("Filename buffer is too big.\n");
                result = TEE_ERROR_BAD_PARAMETERS;
            }
        } else {
            EMSG("Could not get the identity handle element %d. Or the CA is "
                 "already initialized.\n", index_ih);
            result = TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        EMSG("Bad parameters types: 0x%x.\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_ca_free(struct ca_handle_t* ca_h)
{
    TEE_Result result = 0;

    if (ca_h != NULL) {
        if (ca_h->initialized) {
            mbedtls_x509_crt_free(&(ca_h->cert));
            ca_h->initialized = false;
            result = TEE_SUCCESS;
        } else {
            EMSG("Given element has no certificate initialized.\n");
            result = TEE_ERROR_NO_DATA;
        }
    } else {
        EMSG("Pointer to ca handle is NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_ca_unload(uint32_t parameters_type,
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
            result = dsec_ta_ih_ca_free(&(ih->ca_handle));
        } else {
            EMSG("Pointer to Identity Handle is NULL.\n");
            result = TEE_ERROR_NO_DATA;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_ca_get_sn(uint32_t parameters_type,
                                TEE_Param parameters[2])
{
    TEE_Result result = 0;

    uint32_t index_ih = 0;
    const struct identity_handle_t* ih = NULL;
    const mbedtls_x509_crt* cert = NULL;
    /* Size of the output buffer that was allocated */
    size_t output_length = 0;
    char* output_buffer = NULL;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {

        index_ih = (int32_t)parameters[1].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        if ((ih != NULL) && ih->ca_handle.initialized) {
            output_buffer = parameters[0].memref.buffer;
            output_length = parameters[0].memref.size;
            cert = &(ih->ca_handle.cert);

            result = dsec_ta_cert_get_sn(output_buffer, &output_length, cert);
            if (result == TEE_SUCCESS) {
                parameters[0].memref.size = output_length;
            } else {
                /* Return the result from dsec_ta_cert_get_sn */
                parameters[0].memref.size = 0;
            }

        } else {
            EMSG("Index: 0x%x is invalid or has no CA initialized\n", index_ih);
            result = TEE_ERROR_NO_DATA;
            parameters[0].memref.size = 0;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_ca_get_signature_algorithm(uint32_t parameters_type,
                                                 TEE_Param parameters[2])
{
    TEE_Result result = 0;
    uint32_t index_ih = 0;
    const struct identity_handle_t* ih = NULL;
    const mbedtls_x509_crt* cert = NULL;
    /* Size of the output buffer that was allocated */
    size_t output_length = 0;
    char* output_buffer = NULL;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {

        index_ih = (int32_t)parameters[1].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        if ((ih != NULL) && ih->ca_handle.initialized) {
            output_buffer = parameters[0].memref.buffer;
            output_length = parameters[0].memref.size;
            cert = &(ih->ca_handle.cert);

            result = dsec_ta_cert_get_signature_algorithm(output_buffer,
                                                          &output_length,
                                                          cert);

            if (result == TEE_SUCCESS) {
                parameters[0].memref.size = output_length;
            } else {
                /* Return the result from last function */
                parameters[0].memref.size = 0;
            }

        } else {
            EMSG("Index: 0x%x is invalid or has no CA initialized\n", index_ih);
            parameters[0].memref.size = 0;
            result = TEE_ERROR_NO_DATA;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
