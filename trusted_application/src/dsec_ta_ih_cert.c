/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_ih_cert.h>
#include <dsec_ta_ih.h>
#include <dsec_ta_manage_object.h>
#include <dsec_util.h>
#include <mbedtls/base64.h>

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

TEE_Result dsec_ta_ih_cert_get(uint32_t parameters_type,
                               TEE_Param parameters[2])
{
    TEE_Result result = 0;

    int32_t index_ih = 0;
    const struct identity_handle_t* ih = NULL;

    int mbedtls_return = 0;
    const mbedtls_x509_crt* cert = NULL;
    /* Size of the output buffer that was allocated */
    size_t output_length = 0;
    /* Minimal size that should be allocated for the output buffer */
    size_t minimal_output_buffer_length = 0;
    /* Output size of the certificate in base64 without the headers */
    size_t output_buffer_length = 0;
    /* Output buffer containing the extracted certificate without the headers */
    unsigned char* output_buffer;
    /* Number of output bytes in the output_buffer */
    uint32_t written_bytes = 0;

    /* Array containing the header "-----BEGIN CERTIFICATE-----\n" */
    const char prefix[] = {'-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N',
                           ' ', 'C', 'E', 'R', 'T', 'I', 'F', 'I', 'C', 'A',
                           'T', 'E', '-', '-', '-', '-', '-', '\n'};
    /* Array containing the header "\n-----END CERTIFICATE-----\0" */
    const char suffix[] = {'\n', '-', '-', '-', '-', '-', 'E', 'N', 'D',
                           ' ',  'C', 'E', 'R', 'T', 'I', 'F', 'I', 'C',
                           'A',  'T', 'E', '-', '-', '-', '-', '-', '\0'};

    size_t base64_length = 0;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_ih = (int32_t)parameters[1].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        if (ih != NULL) {

            if (ih->cert_handle.initialized) {

                cert = &(ih->cert_handle.cert);
                output_length = parameters[0].memref.size;

                /* Output size of base64 for N bytes is ceil(4*N / 3) */
                base64_length = ((4U * cert->raw.len / 3U) + 3U) & (~3U);

                minimal_output_buffer_length = DSEC_ARRAY_SIZE(prefix) +
                                               base64_length +
                                               DSEC_ARRAY_SIZE(suffix);

                if (output_length >= minimal_output_buffer_length) {
                    output_buffer = (unsigned char*)parameters[0].memref.buffer;
                    /* Set size of output buffer to 0 */
                    parameters[0].memref.size = 0;
                    for (uint32_t i = 0; i < DSEC_ARRAY_SIZE(prefix); i++) {
                        output_buffer[written_bytes] = prefix[i];
                        written_bytes++;
                    }

                    mbedtls_return =
                        mbedtls_base64_encode(output_buffer + written_bytes,
                                              output_length,
                                              &output_buffer_length,
                                              cert->raw.p,
                                              cert->raw.len);

                    written_bytes = written_bytes + output_buffer_length;
                    for (uint32_t i = 0; i < DSEC_ARRAY_SIZE(suffix); i++) {
                        output_buffer[written_bytes] = suffix[i];
                        written_bytes++;
                    }

                    if (mbedtls_return == 0) {

                        /*
                         * Variable written_bytes is the size of the array as
                         * the array is starting at index 0.
                         */
                        parameters[0].memref.size = written_bytes;
                        result = TEE_SUCCESS;
                        DMSG("Certificate has been correctly set.\n");
                    } else {
                        result = TEE_ERROR_BAD_FORMAT;
                        EMSG("Could not parse the certificate stored.\n");
                        /*
                         * Size of the output buffer is updated at the end of
                         * the function.
                         */
                    }

                } else {
                    EMSG("Output array is too short.\n");
                    result = TEE_ERROR_SHORT_BUFFER;
                }

            } else {
                 EMSG("Certificate is not set.\n");
                 result = TEE_ERROR_NO_DATA;
            }

        } else {
            EMSG("Given index: 0x%x is invalid.\n", index_ih);
            result = TEE_ERROR_NO_DATA;
        }

        /*
         * Set the size of the output buffer to 0 if an error occurred.
         */
        if (result != TEE_SUCCESS) {
            parameters[0].memref.size = 0;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_get_sn(uint32_t parameters_type,
                                  TEE_Param parameters[2])
{
    TEE_Result result = 0;
    int mbedtls_return = 0;
    uint32_t index_ih = 0;
    const struct identity_handle_t* ih = NULL;

    const mbedtls_x509_crt* cert = NULL;
    /* Size of the output buffer that was allocated */
    size_t output_length = 0;
    char* output_buffer = NULL;

    const size_t CERT_MAX_SUBJECT_NAME_SIZE = 2048;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {

        index_ih = (int32_t)parameters[1].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        if (ih != NULL) {
            if (ih->cert_handle.initialized) {
                output_length = parameters[0].memref.size;
                cert = &(ih->cert_handle.cert);
                if (output_length >= CERT_MAX_SUBJECT_NAME_SIZE) {
                    output_buffer = parameters[0].memref.buffer;

                    const mbedtls_x509_name* ca_subject_name = &cert->subject;
                    mbedtls_return =
                        mbedtls_x509_dn_gets(output_buffer,
                                             CERT_MAX_SUBJECT_NAME_SIZE,
                                             ca_subject_name);
                    /*
                     * The return value contains the length of the string
                     * without '\0' character or a negative error code.
                     */
                    if (mbedtls_return >= 0) {
                        result = TEE_SUCCESS;
                        parameters[0].memref.size = mbedtls_return + 1;
                    } else {
                        EMSG("An error occurred when getting the field 0x%x\n",
                             mbedtls_return);

                        result = TEE_ERROR_BAD_FORMAT;
                        parameters[0].memref.size = 0;
                    }

                } else {
                    EMSG("Output array is too short.\n");
                    result = TEE_ERROR_SHORT_BUFFER;
                }

            } else {
                EMSG("Certificate is not set.\n");
                result = TEE_ERROR_NO_DATA;
            }

        } else {
            EMSG("Index: 0x%x is invalid.\n", index_ih);
            result = TEE_ERROR_BAD_PARAMETERS;
        }

        /*
         * Set the size of the output buffer to 0 if an error occurred.
         */
        if (result != TEE_SUCCESS) {
            parameters[0].memref.size = 0;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_get_signature_algorithm(uint32_t parameters_type,
                                                   TEE_Param parameters[2])
{
    TEE_Result result = 0;
    int mbedtls_return = 0;
    uint32_t index_ih = 0;
    const struct identity_handle_t* ih = NULL;

    const mbedtls_x509_crt* cert = NULL;
    /* Size of the output buffer that was allocated */
    size_t output_length = 0;
    char* output_buffer = NULL;

    const size_t CERT_MAX_SUBJECT_NAME_SIZE = 64;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {

        index_ih = (int32_t)parameters[1].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        if ((ih != NULL) && ih->cert_handle.initialized) {
            output_length = parameters[0].memref.size;
            cert = &(ih->cert_handle.cert);
            if (output_length > CERT_MAX_SUBJECT_NAME_SIZE) {
                output_buffer = parameters[0].memref.buffer;

                const mbedtls_x509_buf* sig_oid = &cert->sig_oid;
                mbedtls_return = mbedtls_x509_sig_alg_gets(output_buffer,
                                                           output_length,
                                                           sig_oid,
                                                           cert->sig_pk,
                                                           cert->sig_md,
                                                           cert->sig_opts);

                /*
                 * The return value contains the length of the string without
                 * '\0' character or a negative error code.
                 */
                if (mbedtls_return >= 0) {
                    result = TEE_SUCCESS;
                    parameters[0].memref.size = mbedtls_return + 1;
                } else {
                    EMSG("An error occurred when getting the field 0x%x\n",
                         mbedtls_return);

                    result = TEE_ERROR_BAD_FORMAT;
                    parameters[0].memref.size = 0;
                }

            } else {
                EMSG("Output array is too short.\n");
                result = TEE_ERROR_SHORT_BUFFER;
            }

        } else {
            EMSG("Index: 0x%x is invalid or certificate is not set.\n",
                 index_ih);

            result = TEE_ERROR_NO_DATA;
        }

        /* Set the size of the output buffer to 0 if an error occurred. */
        if (result != TEE_SUCCESS) {
            parameters[0].memref.size = 0;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

