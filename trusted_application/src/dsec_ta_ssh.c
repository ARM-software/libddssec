/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_ta_ssh.h>
#include <dsec_ta_dh.h>
#include <dsec_ta_hh.h>
#include <dsec_util.h>
#include <mbedtls/sha256.h>
#include <tee_api.h>

static struct shared_secret_handle_t store[DSEC_TA_MAX_SHARED_SECRET_HANDLE];
static uint32_t allocated_handle = 0;

/*
 * Returns a valid index to an element from the array which has not been
 * initialized.
 */
static int32_t find_free_element(void)
{
    int32_t index = 0;

    index = TEE_ERROR_NO_DATA;
    for (uint32_t id = 0; id < DSEC_TA_MAX_SHARED_SECRET_HANDLE; id++) {
        if (!store[id].initialized) {
            index = (int32_t)id;
            break;
        }
    }

    return index;
}

/*
 * Checks if a given index leads to an initialized handle (i.e. not
 * out-of-bounds and has its boolean flag initialized set.
 */
static bool ssh_is_valid(int32_t index)
{
    return (index >= 0) &&
           ((uint32_t)index < DSEC_TA_MAX_SHARED_SECRET_HANDLE) &&
           store[index].initialized;
}

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
    TEE_Result result = 0;
    TEE_ObjectHandle shared_key_object;

    uint8_t shared_key[DSEC_TA_MAX_SHARED_KEY_SIZE];
    uint32_t shared_key_size = DSEC_TA_MAX_SHARED_KEY_SIZE;

    shared_key_handle->initialized = false;
    shared_key_handle->data_size = 0;

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
                &shared_key_object);

            if (result == TEE_SUCCESS) {
                /* Set the remote node's public key as attribute. */
                TEE_InitRefAttribute(&attribute,
                                     TEE_ATTR_DH_PUBLIC_VALUE,
                                     dh_remote_handle->key,
                                     dh_remote_handle->key_size);

                TEE_DeriveKey(operation,
                              &attribute,
                              1 /* number attributes */,
                              shared_key_object);

                /*
                 * Find the key size of the generated secret. This function
                 * is also a check to see if the key was generated properly.
                 */
                result = TEE_GetObjectBufferAttribute(
                    shared_key_object,
                    TEE_ATTR_SECRET_VALUE,
                    shared_key,
                    &shared_key_size);

                if (result == TEE_SUCCESS) {
                    shared_key_handle->initialized = true;
                    shared_key_handle->data_size = 32 /* SHA256 is 32 bytes */;
                    mbedtls_sha256(shared_key,
                                   shared_key_size,
                                   shared_key_handle->data,
                                   0 /* is224 */);

                } else {
                    EMSG("Could not get the shared secret key size.\n");
                    /* Return the result from TEE_GetObjectInfo1 */
                }

            TEE_FreeTransientObject(shared_key_object);

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
                                 TEE_Param parameters[2])
{
    TEE_Result result = 0;
    uint32_t index_hh = 0;
    struct handshake_handle_t* hh = NULL;
    const struct dh_pair_handle_t* dh_local_handle = NULL;
    const struct dh_public_handle_t* dh_remote_handle = NULL;
    struct shared_secret_handle_t* ssh = NULL;
    struct shared_key_handle_t* skh = NULL;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index_hh = (int32_t) parameters[1].value.a;
        parameters[0].value.a = (uint32_t)(-1);
        hh = dsec_ta_get_handshake_handle(index_hh);

        if ((hh != NULL) && hh->initialized) {

            dh_local_handle = &(hh->dh_pair_handle);
            dh_remote_handle = &(hh->dh_public_handle);
            ssh = dsec_ta_ssh_get(hh->shared_secret_id);
            if (ssh != NULL) {
                skh = &(ssh->shared_key_handle);

                if (dh_local_handle->initialized &&
                    dh_remote_handle->initialized &&
                    !skh->initialized) {

                    result = ss_derive(dh_local_handle, dh_remote_handle, skh);
                    if (result == TEE_SUCCESS) {
                        parameters[0].value.a = hh->shared_secret_id;

                        /*
                         * Free the Handshake handle elements but not the shared
                         * secret handle as it is returned.
                         * From this point, the Handshake Handle cannot be used.
                         */
                         hh->shared_secret_id = -1;
                    }

                } else {
                    EMSG("Elements not initialized or Shared Key is set.\n");
                    result = TEE_ERROR_NO_DATA;
                }
            } else {
                EMSG("Could not retrieve Shared Key handle.\n");
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
        shared_secret_handle->shared_key_handle.initialized = false;
        shared_secret_handle->challenge1_handle.initialized = false;
        shared_secret_handle->challenge2_handle.initialized = false;

        result = TEE_SUCCESS;
    } else {
        EMSG("Shared Secret Handle is not set.\n");
        result = TEE_ERROR_NO_DATA;
    }

    return result;
}

TEE_Result dsec_ta_ssh_create(int32_t* index)
{
    TEE_Result result = TEE_SUCCESS;

    if (index != NULL) {
        *index = find_free_element();
        if (*index >= 0) {
            store[*index].initialized = true;
            store[*index].shared_key_handle.initialized = false;
            store[*index].challenge1_handle.initialized = false;
            store[*index].challenge2_handle.initialized = false;

            allocated_handle++;
            result = TEE_SUCCESS;
        } else {
            EMSG("Cannot allocate memory to create a new handle.\n");
            result = TEE_ERROR_OUT_OF_MEMORY;
        }
    } else {
        EMSG("Specified index is NULL.\n");
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

struct shared_secret_handle_t* dsec_ta_ssh_get(int32_t index)
{
    struct shared_secret_handle_t* return_ssh = NULL;

    if (ssh_is_valid(index)) {
        return_ssh = &(store[index]);
    }

    return return_ssh;
}

TEE_Result dsec_ta_ssh_get_info(uint32_t parameters_type,
                                TEE_Param parameters[1])
{
    TEE_Result result = TEE_SUCCESS;

    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        parameters[0].value.a = DSEC_TA_MAX_SHARED_SECRET_HANDLE;
        parameters[0].value.b = allocated_handle;
        result = TEE_SUCCESS;
    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ssh_unload(uint32_t parameters_type,
                              const TEE_Param parameters[1])
{
    TEE_Result result = 0;
    uint32_t index = 0;
    struct shared_secret_handle_t* ssh = NULL;
    const uint32_t expected_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE,
                                                    TEE_PARAM_TYPE_NONE);

    if (parameters_type == expected_types) {
        index = (int32_t)parameters[0].value.a;
        ssh = dsec_ta_ssh_get(index);

        if (ssh != NULL) {
            result = dsec_ta_ssh_free(ssh);
        } else {
            EMSG("Shared Secret Handle is invalid.\n");
            result = TEE_ERROR_BAD_PARAMETERS;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

TEE_Result dsec_ta_ssh_get_data(uint32_t parameters_type,
                                TEE_Param parameters[4])
{
    TEE_Result result = 0;
    int32_t index = 0;
    void* output_hash_shared_key = NULL;
    uint32_t hash_shared_key_size = 0;
    void* output_challenge1 = NULL;
    uint32_t challenge1_size = 0;
    void* output_challenge2 = NULL;
    uint32_t challenge2_size = 0;
    const struct shared_secret_handle_t* ssh = NULL;

    const uint32_t expected_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_INPUT);

    if (parameters_type == expected_types) {
        index = (int32_t)parameters[3].value.a;
        ssh = dsec_ta_ssh_get(index);

        if ((ssh != NULL) &&
            ssh->initialized &&
            ssh->shared_key_handle.initialized &&
            ssh->challenge1_handle.initialized &&
            ssh->challenge2_handle.initialized) {

            output_hash_shared_key = parameters[0].memref.buffer;
            hash_shared_key_size = parameters[0].memref.size;
            output_challenge1 = parameters[1].memref.buffer;
            challenge1_size = parameters[1].memref.size;
            output_challenge2 = parameters[2].memref.buffer;
            challenge2_size = parameters[2].memref.size;

            if ((challenge1_size >= ssh->challenge1_handle.data_size) &&
                (challenge2_size >= ssh->challenge2_handle.data_size) &&
                (hash_shared_key_size >= ssh->shared_key_handle.data_size)) {

                TEE_MemMove(output_hash_shared_key,
                            ssh->shared_key_handle.data,
                            ssh->shared_key_handle.data_size);

                parameters[0].memref.size = ssh->shared_key_handle.data_size;

                TEE_MemMove(output_challenge1,
                            ssh->challenge1_handle.data,
                            ssh->challenge1_handle.data_size);

                parameters[1].memref.size = ssh->challenge1_handle.data_size;

                TEE_MemMove(output_challenge2,
                            ssh->challenge2_handle.data,
                            ssh->challenge2_handle.data_size);

                parameters[2].memref.size = ssh->challenge2_handle.data_size;

                result = TEE_SUCCESS;

            } else {
                EMSG("Given buffers are not big enough.\n");
                result = TEE_ERROR_SHORT_BUFFER;
            }

        } else {
            EMSG("Handle is invalid or has un-initialized fields.\n");
            result = TEE_ERROR_NO_DATA;
        }

        if (result != TEE_SUCCESS) {
            parameters[0].memref.size = 0;
            parameters[1].memref.size = 0;
            parameters[2].memref.size = 0;
        }

    } else {
        EMSG("Bad parameters types: 0x%x\n", parameters_type);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}
