/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_digest.h>
#include <dsec_ta_ih_cert.h>
#include <dsec_ta_ih.h>
#include <dsec_ta_manage_object.h>
#include <dsec_errno.h>
#include <mbedtls/base64.h>

/*
 * This function checks the given inputs to make sure they are valid and can be
 * used as inputs for cert_signature_verify(...)
 */
static TEE_Result cert_signature_verify_check_input(
    const unsigned char* input,
    size_t input_size,
    const unsigned char* signature,
    size_t signature_size)
{

    TEE_Result result = 0;
    uint32_t bitlength = 0;
    size_t max_signature_size = 0;
    const size_t MAX_BUFFER_SIZE = 1048576UL;
    const mbedtls_ecp_curve_info* curve_info = NULL;

    curve_info = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);
    if ((input != NULL) && (input_size < MAX_BUFFER_SIZE)) {

        if (curve_info != NULL) {
            /*
             * If the bitlength of the message hash is larger than the bitlength
             * of the group order, then the hash is truncated as defined in
             * Standards for Efficient Cryptography Group (SECG):
             *     SEC1 Elliptic Curve Cryptography, section 4.1.4, step 3.
             */
            bitlength = curve_info->bit_size;
            if (bitlength <= (DSEC_TA_SHA256_SIZE * 8)) {
                /*
                 * The given signature buffer should have a size of 2 times
                 * the size of the curve used, plus 9.
                 */
                max_signature_size = (2 * (bitlength / 8)) + 9;

                if ((signature != NULL) &&
                    (signature_size <= max_signature_size)) {

                    result = TEE_SUCCESS;
                } else {
                    EMSG("Signature size: 0x%lx is too big\n", signature_size);
                    result = TEE_ERROR_BAD_PARAMETERS;
                }

            } else {
                EMSG("Hash size is larger than the size of the group order.\n");
                result = TEE_ERROR_BAD_FORMAT;
            }

        } else {
            EMSG("Could not retrieve curse information.\n");
            result = TEE_ERROR_NOT_SUPPORTED;
        }

    } else {
        EMSG("Given buffer size (0x%lx) is too big or input is NULL.\n",
              input_size);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

/*
 * Create a SHA256 of the input buffer and use the given public key on the given
 * signature to check if it matches the computed SHA256.
 * Note: This function is not making any checks on its input and assumes that
 *     all its arguments are valid. This function should be called after
 *     cert_signature_verify_check_input(...).
 */
static TEE_Result cert_signature_verify(const mbedtls_pk_context* public_key,
                                        const unsigned char* input,
                                        size_t input_size,
                                        const unsigned char* signature,
                                        size_t signature_size)
{

    TEE_Result result = 0;
    int result_mbedtls = 0;
    uint8_t sha256_data[DSEC_TA_SHA256_SIZE] = {0};
    mbedtls_ecdsa_context ecdsa_public_context;

    mbedtls_ecdsa_init(&ecdsa_public_context);
    result_mbedtls = mbedtls_ecdsa_from_keypair(&ecdsa_public_context,
                                                public_key->pk_ctx);

    if (result_mbedtls == 0) {

        int32_t result_sha256 = dsec_ta_digest_sha256(sha256_data,
                                                      input,
                                                      input_size);

        if (result_sha256 == DSEC_SUCCESS) {
            /*
             * Check if the sha256 of the given data `input` and
             * the given signature match the computed signature
             * with the key specified.
             */
            result_mbedtls = mbedtls_ecdsa_read_signature(&ecdsa_public_context,
                                                          sha256_data,
                                                          DSEC_TA_SHA256_SIZE,
                                                          signature,
                                                          signature_size);

            if (result_mbedtls == 0) {
                result = TEE_SUCCESS;
            } else {
                EMSG("Signature is invalid: 0x%x.\n", result_mbedtls);
                result = TEE_ERROR_SECURITY;
            }
        } else {
            EMSG("Could not perform the digest for signing the certificate.\n");
            result = TEE_ERROR_SECURITY;
        }
        mbedtls_ecdsa_free(&ecdsa_public_context);
    } else {
        EMSG("Could not create an ECDSA context.\n");
        result = TEE_ERROR_SECURITY;
    }

    return result;
}

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

    const size_t prefix_len = (sizeof(prefix)/sizeof(prefix[0]));

    /* Array containing the header "\n-----END CERTIFICATE-----\0" */
    const char suffix[] = {'\n', '-', '-', '-', '-', '-', 'E', 'N', 'D',
                           ' ',  'C', 'E', 'R', 'T', 'I', 'F', 'I', 'C',
                           'A',  'T', 'E', '-', '-', '-', '-', '-', '\0'};

    const size_t suffix_len = (sizeof(suffix)/sizeof(suffix[0]));

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

                minimal_output_buffer_length = prefix_len +
                                               base64_length +
                                               suffix_len;

                if (output_length >= minimal_output_buffer_length) {
                    output_buffer = (unsigned char*)parameters[0].memref.buffer;
                    /* Set size of output buffer to 0 */
                    parameters[0].memref.size = 0;
                    for (uint32_t i = 0;
                         i < prefix_len;
                         i++) {

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
                    for (uint32_t i = 0;
                         i < suffix_len;
                         i++) {

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

TEE_Result dsec_ta_cert_get_sn(char* output_buffer,
                               size_t* output_length,
                               const mbedtls_x509_crt* cert)
{
    const size_t CERT_MAX_SUBJECT_NAME_SIZE = 2048;
    TEE_Result result = 0;
    int mbedtls_return = 0;
    const mbedtls_x509_name* subject_name = NULL;

    if ((output_buffer != NULL) && (output_length != NULL) && (cert != NULL)) {
        if (*output_length >= CERT_MAX_SUBJECT_NAME_SIZE) {

            subject_name = &(cert->subject);
            mbedtls_return = mbedtls_x509_dn_gets(output_buffer,
                                                  CERT_MAX_SUBJECT_NAME_SIZE,
                                                  subject_name);
            /*
             * The return value contains the length of the string
             * without '\0' character or a negative error code.
             */
            if (mbedtls_return >= 0) {
                result = TEE_SUCCESS;
                *output_length = mbedtls_return + 1;
            } else {
                EMSG("An error occurred when getting the field 0x%x\n",
                     mbedtls_return);

                result = TEE_ERROR_BAD_FORMAT;
                *output_length = 0;
            }

        } else {
            EMSG("Output array is too short.\n");
            result = TEE_ERROR_SHORT_BUFFER;
            *output_length = 0;
        }

    } else {
        EMSG("Given parameters are invalid.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_get_sn(uint32_t parameters_type,
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

        if ((ih != NULL) && ih->cert_handle.initialized) {
            output_buffer = parameters[0].memref.buffer;
            output_length = parameters[0].memref.size;
            cert = &(ih->cert_handle.cert);
            result = dsec_ta_cert_get_sn(output_buffer, &output_length, cert);
            parameters[0].memref.size = output_length;
        } else {
            EMSG("Index: 0x%x is invalid.\n", index_ih);
            result = TEE_ERROR_NO_DATA;
            parameters[0].memref.size = 0;
        }
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_cert_get_signature_algorithm(char* output_buffer,
                                                size_t* output_length,
                                                const mbedtls_x509_crt* cert)
{
    const size_t CERT_MAX_SUBJECT_NAME_SIZE = 64;
    TEE_Result result = 0;
    int mbedtls_return = 0;
    const mbedtls_x509_buf* sig_oid = NULL;

    if ((output_buffer != NULL) && (output_length != NULL) && (cert != NULL)) {
        if (*output_length >= CERT_MAX_SUBJECT_NAME_SIZE) {
            sig_oid = &(cert->sig_oid);
            mbedtls_return = mbedtls_x509_sig_alg_gets(output_buffer,
                                                       *output_length,
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
                *output_length = mbedtls_return + 1;
            } else {
                EMSG("An error occurred when getting the field: 0x%x\n",
                     mbedtls_return);

                result = TEE_ERROR_BAD_FORMAT;
                *output_length = 0;
            }

        } else {
            EMSG("Output array is too short.\n");
            result = TEE_ERROR_SHORT_BUFFER;
            *output_length = 0;
        }

    } else {
        EMSG("Given parameters are invalid.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_get_signature_algorithm(uint32_t parameters_type,
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

        if ((ih != NULL) && ih->cert_handle.initialized) {
            output_buffer = parameters[0].memref.buffer;
            output_length = parameters[0].memref.size;
            cert = &(ih->cert_handle.cert);

            result = dsec_ta_cert_get_signature_algorithm(output_buffer,
                                                          &output_length,
                                                          cert);

            if (result == TEE_SUCCESS) {
                parameters[0].memref.size = output_length;
            } else {
                parameters[0].memref.size = 0;
            }

        } else {
            EMSG("Index: 0x%x is invalid or certificate is not set.\n",
                 index_ih);

            parameters[0].memref.size = 0;
            result = TEE_ERROR_NO_DATA;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_load_from_buffer(uint32_t parameters_type,
                                            const TEE_Param parameters[3])
{

    TEE_Result result = 0;

    uint32_t index_rih = 0;
    struct identity_handle_t* rih = NULL;
    uint32_t index_lih = 0;
    struct identity_handle_t* lih = NULL;

    size_t input_length = 0;
    const char* input_buffer = NULL;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {

        index_rih = (int32_t)parameters[0].value.a;
        rih = dsec_ta_get_identity_handle(index_rih);

        input_length = (size_t)parameters[1].memref.size;
        input_buffer = (char*)parameters[1].memref.buffer;

        index_lih = (int32_t)parameters[2].value.a;
        lih = dsec_ta_get_identity_handle(index_lih);

        if ((rih != NULL) &&
            !rih->cert_handle.initialized &&
            !rih->ca_handle.initialized) {

            if ((lih != NULL) && lih->ca_handle.initialized) {
                result = cert_parse_and_verify(&(rih->cert_handle.cert),
                                               lih,
                                               input_buffer,
                                               input_length);

                if (result == 0) {
                    rih->cert_handle.initialized = true;
                } else {
                    rih->cert_handle.initialized = false;
                }

                /* Return the given result from the last function called */

            } else {
                EMSG("Index: 0x%x for lih is invalid or Certificate authority "
                     "is not set.\n",
                      index_lih);

                result = TEE_ERROR_BAD_PARAMETERS;
            }

        } else {
            EMSG("Index: 0x%x for rih is invalid or already has a certificate "
                 "set.\n",
                 index_rih);

            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_signature_verify(uint32_t parameters_type,
                                            const TEE_Param parameters[3])
{
    TEE_Result result = 0;
    uint32_t index_rih = 0;
    const struct identity_handle_t* rih = NULL;
    const unsigned char* input = NULL;
    size_t input_size = 0;
    const unsigned char* signature = NULL;
    size_t signature_size = 0;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {

        index_rih = (int32_t)parameters[0].value.a;
        rih = dsec_ta_get_identity_handle(index_rih);
        if (rih != NULL) {
            /*
             * Make sure this is a remote identity handle and it has a valid
             * certificate
             */
            if (rih->cert_handle.initialized) {

                input = parameters[1].memref.buffer;
                input_size = parameters[1].memref.size;

                signature = parameters[2].memref.buffer;
                signature_size = parameters[2].memref.size;

                result = cert_signature_verify_check_input(input,
                                                           input_size,
                                                           signature,
                                                           signature_size);

                if (result == TEE_SUCCESS) {
                    result = cert_signature_verify(&(rih->cert_handle.cert.pk),
                                                   input,
                                                   input_size,
                                                   signature,
                                                   signature_size);
                }

            } else {
                EMSG("Certificate is not set or this is not a remote ih.\n");
                result = TEE_ERROR_NO_DATA;
            }

        } else {
            EMSG("Identity Handle is invalid.\n");
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_get_sha256_sn(uint32_t parameters_type,
                                         TEE_Param parameters[2])
{
    TEE_Result result = 0;
    uint32_t index_ih = 0;
    const struct identity_handle_t* ih = NULL;

    const mbedtls_x509_crt* cert = NULL;
    mbedtls_x509_buf raw_sn;
    /* Size of the output buffer that was allocated */
    size_t output_length = 0;
    uint8_t* output_buffer = NULL;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {

        index_ih = (int32_t)parameters[1].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        if ((ih != NULL) && ih->cert_handle.initialized) {
            output_buffer = parameters[0].memref.buffer;
            output_length = parameters[0].memref.size;

            parameters[0].memref.size = 0;
            if (output_length >= DSEC_TA_SHA256_SIZE) {
                int32_t result_sha256 = 0;

                cert = &(ih->cert_handle.cert);
                raw_sn = cert->subject_raw;
                result_sha256 = dsec_ta_digest_sha256(output_buffer,
                                                      raw_sn.p,
                                                      raw_sn.len);

                if (result_sha256 == DSEC_SUCCESS) {
                    parameters[0].memref.size = DSEC_TA_SHA256_SIZE;
                    result = TEE_SUCCESS;
                } else {
                    parameters[0].memref.size = -1;
                    EMSG("Could not perform the digest for the subject"
                         " name.\n");

                    result = TEE_ERROR_SECURITY;
                }

            } else {
                EMSG("Output buffer is too small.\n");
                parameters[0].memref.size = 0;
                result = TEE_ERROR_SHORT_BUFFER;
            }

        } else {
            EMSG("Index: 0x%x is too invalid or certificate is not set.\n",
                 index_ih);

            parameters[0].memref.size = 0;
            result = TEE_ERROR_NO_DATA;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ih_cert_get_raw_sn(uint32_t parameters_type,
                                      TEE_Param parameters[2])
{
    TEE_Result result = 0;
    uint32_t index_ih = 0;
    const struct identity_handle_t* ih = NULL;
    const mbedtls_x509_buf* raw_sn = NULL;
    unsigned char* output_p = NULL;
    uint32_t output_p_length = 0;

    const uint32_t expected_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {

        index_ih = (int32_t)parameters[1].value.a;
        ih = dsec_ta_get_identity_handle(index_ih);

        if ((ih != NULL) && ih->cert_handle.initialized) {
            output_p = parameters[0].memref.buffer;
            output_p_length = parameters[0].memref.size;
            raw_sn = &(ih->cert_handle.cert.subject_raw);

            if (output_p_length >= (raw_sn->len + 1)) {
                TEE_MemMove(output_p, raw_sn->p, raw_sn->len + 1);
                parameters[0].memref.size = raw_sn->len + 1;
                result = TEE_SUCCESS;
            } else {
                EMSG("Output buffer too small.\n");
                parameters[0].memref.size = 0;
                result = TEE_ERROR_SHORT_BUFFER;
            }

        } else {
            EMSG("Index: 0x%x is invalid or certificate is not set.\n",
                 index_ih);

            parameters[0].memref.size = 0;
            result = TEE_ERROR_NO_DATA;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
