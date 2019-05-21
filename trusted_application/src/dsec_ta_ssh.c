/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_ssh.h>
#include <dsec_ta_dh.h>
#include <dsec_ta_hh.h>
#include <tee_api.h>

/*
 * This function calls the TEE API to derive the shared key and updates the
 * handle shared_key_handle_t to setup the key.
 * Note: This function trusts the inputs from its caller.
 */
static TEE_Result ss_derive(const struct dh_pair_handle_t* dh_local_handle,
                            const struct dh_public_handle_t* dh_remote_handle,
                            struct shared_key_handle_t* shared_key_handle)
{
    TEE_Attribute attribute = {0};
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    TEE_ObjectInfo object_info = {0};
    TEE_Result result = 0;

    shared_key_handle->initialized = false;
    shared_key_handle->shared_key_size = 0;

    /*
     * Allocate operation for a Diffie Hellman key derivation of a shared
     * secret.
     */
    result = TEE_AllocateOperation(&operation,
                                   TEE_ALG_DH_DERIVE_SHARED_SECRET,
                                   TEE_MODE_DERIVE,
                                   DSEC_TA_DH_MAX_KEY_BITS);

    if (result == TEE_SUCCESS) {
        /*
         * Set the operation key to the DH key pair generated for the local
         * node.
         */
        result = TEE_SetOperationKey(operation, dh_local_handle->key_pair);
        if (result == TEE_SUCCESS) {

            /* Allocate the shared secret OPTEE structure. */
            result = TEE_AllocateTransientObject(
                TEE_TYPE_GENERIC_SECRET,
                DSEC_TA_DH_MAX_KEY_BITS,
                &(shared_key_handle->shared_key));

            if (result == TEE_SUCCESS) {
                /* Set the remote node's public key as attribute. */
                TEE_InitRefAttribute(&attribute,
                                     TEE_ATTR_DH_PUBLIC_VALUE,
                                     dh_remote_handle->key,
                                     dh_remote_handle->key_size);

                TEE_DeriveKey(operation,
                              &attribute,
                              1 /* number attributes */,
                              shared_key_handle->shared_key);

                /*
                 * Find the key size of the generated secret. This function
                 * is also a check to see if the key was generated properly.
                 */
                result = TEE_GetObjectInfo1(shared_key_handle->shared_key,
                                            &object_info);

                if (result == TEE_SUCCESS) {
                    shared_key_handle->initialized = true;
                    shared_key_handle->shared_key_size =
                        object_info.maxObjectSize;

                } else {
                    EMSG("Could not get the shared secret key size.\n");
                    TEE_FreeTransientObject(shared_key_handle->shared_key);
                    /* Return the result from TEE_GetObjectInfo1 */
                }

            } else {
                EMSG("Could not allocate object for shared secret.\n");
                /* Return the result from TEE_AllocateTransientObject */
            }

        } else {
            EMSG("Could not set operation key.\n");
            /* Return the result from TEE_SetOperationKey */
        }

        TEE_FreeOperation(operation);

    } else {
        EMSG("Cannot allocate space for derive operation.\n");
        /* Return the result from TEE_AllocateOperation */
    }

    return result;
}

TEE_Result dsec_ta_hh_ssh_derive(uint32_t parameters_type,
                                 TEE_Param parameters[1])
{
    TEE_Result result = 0;
    uint32_t index_hh = 0;
    struct handshake_handle_t* hh = NULL;
    const struct dh_pair_handle_t* dh_local_handle = NULL;
    const struct dh_public_handle_t* dh_remote_handle = NULL;
    struct shared_key_handle_t* shared_key_handle = NULL;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_hh = (int32_t)parameters[0].value.a;
        hh = dsec_ta_get_handshake_handle(index_hh);
        if ((hh != NULL) && hh->initialized) {

            dh_local_handle = &(hh->dh_pair_handle);
            dh_remote_handle = &(hh->dh_public_handle);
            shared_key_handle = &(hh->shared_secret_handle.shared_key_handle);

            if (dh_local_handle->initialized &&
                dh_remote_handle->initialized &&
                !hh->shared_secret_handle.shared_key_handle.initialized) {

                result = ss_derive(dh_local_handle,
                                   dh_remote_handle,
                                   shared_key_handle);

            } else {
                EMSG("Elements are not initialized or Shared Key is set.\n");
                result = TEE_ERROR_NO_DATA;
            }

        } else {
            EMSG("Handshake Handle is invalid.\n");
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x.\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ssh_free(
    struct shared_secret_handle_t* shared_secret_handle)
{
    TEE_Result result = 0;

    if ((shared_secret_handle != NULL) && shared_secret_handle->initialized) {
        shared_secret_handle->initialized = false;
        TEE_FreeTransientObject(
            shared_secret_handle->shared_key_handle.shared_key);

        result = TEE_SUCCESS;
    } else {
        EMSG("Shared Secret Handle is not set.\n");
        result = TEE_ERROR_NO_DATA;
    }

    return result;
}
