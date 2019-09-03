/*
 * DDS Security library
 * Copyright (c) 2018-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_macros.h>
#include <dsec_ta.h>
#include <dsec_ta_digest.h>
#include <dsec_ta_hh.h>
#include <dsec_ta_ih.h>
#include <dsec_ta_ih_ca.h>
#include <dsec_ta_ih_cert.h>
#include <dsec_ta_ih_privkey.h>
#include <dsec_ta_hmac.h>
#include <dsec_ta_key_material.h>
#include <dsec_ta_manage_object.h>
#include <dsec_ta_session_key.h>
#include <dsec_ta_aes.h>
#include <tee_ta_api.h>
#include <trace.h>

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result result = TEE_SUCCESS;

    DMSG("Creating libddssec's TA");
    result = dsec_ta_hmac_256_init();
    if (result == TEE_SUCCESS) {
        result = dsec_ta_aes_init();
    }

    return result;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("Destroying libddssec's TA");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t ptype,
                                    TEE_Param param[TEE_NUM_PARAMS],
                                    void** session_id_ptr)
{
    DSEC_UNUSED(ptype);
    DSEC_UNUSED(param);
    DSEC_UNUSED(session_id_ptr);

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void* sess_ptr)
{
    DSEC_UNUSED(sess_ptr);
}

TEE_Result TA_InvokeCommandEntryPoint(void* session_id,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[TEE_NUM_PARAMS])
{
    TEE_Result result = 0;
    DSEC_UNUSED(session_id);

    switch (command_id) {

    case DSEC_TA_CMD_IH_CREATE:
        result = dsec_ta_ih_create(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_DELETE:
        result = dsec_ta_ih_delete(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_INFO:
        result = dsec_ta_ih_get_info(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_CA_LOAD:
        result = dsec_ta_ih_ca_load(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_CA_UNLOAD:
        result = dsec_ta_ih_ca_unload(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_CA_GET_SN:
        result = dsec_ta_ih_ca_get_sn(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_CA_GET_SIGNATURE_ALGORITHM:
        result = dsec_ta_ih_ca_get_signature_algorithm(parameters_type,
                                                       parameters);

        break;
    case DSEC_TA_CMD_IH_CERT_LOAD:
        result = dsec_ta_ih_cert_load(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_CERT_UNLOAD:
        result = dsec_ta_ih_cert_unload(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_CERT_GET:
        result = dsec_ta_ih_cert_get(parameters_type, parameters);
         break;
    case DSEC_TA_CMD_IH_CERT_GET_SN:
        result = dsec_ta_ih_cert_get_sn(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_CERT_GET_SIGNATURE_ALGORITHM:
        result = dsec_ta_ih_cert_get_signature_algorithm(parameters_type,
                                                         parameters);

        break;
    case DSEC_TA_CMD_IH_CERT_LOAD_FROM_BUFFER:
        result = dsec_ta_ih_cert_load_from_buffer(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_CERT_GET_SHA256_SN:
        result = dsec_ta_ih_cert_get_sha256_sn(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_CERT_GET_RAW_SN:
        result = dsec_ta_ih_cert_get_raw_sn(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_PRIVKEY_LOAD:
        result = dsec_ta_ih_privkey_load(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_PRIVKEY_UNLOAD:
        result = dsec_ta_ih_privkey_unload(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_CERT_VERIFY:
        result = dsec_ta_ih_cert_signature_verify(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_IH_PRIVKEY_SIGN:
        result = dsec_ta_ih_privkey_sign(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_CREATE:
        result = dsec_ta_hh_create(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_DELETE:
        result = dsec_ta_hh_delete(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_INFO:
        result = dsec_ta_hh_get_info(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_DH_GENERATE_KEYS:
        result = dsec_ta_hh_dh_generate_keys(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_DH_GET_PUBLIC:
        result = dsec_ta_hh_dh_get_public(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_DH_UNLOAD:
        result = dsec_ta_hh_dh_unload(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_DH_SET_PUBLIC:
        result = dsec_ta_hh_dh_set_public(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_SSH_DERIVE:
        result = dsec_ta_hh_ssh_derive(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_CHALLENGE_GENERATE:
        result = dsec_ta_hh_challenge_generate(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_CHALLENGE_GET:
        result = dsec_ta_hh_challenge_get(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_CHALLENGE_SET:
        result = dsec_ta_hh_challenge_set(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_HH_CHALLENGE_UNLOAD:
        result = dsec_ta_hh_challenge_unload(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_SSH_GET_DATA:
        result = dsec_ta_ssh_get_data(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_SSH_DELETE:
        result = dsec_ta_ssh_unload(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_SSH_INFO:
        result = dsec_ta_ssh_get_info(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_KM_CREATE:
        result = dsec_ta_key_material_create(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_KM_COPY:
        result = dsec_ta_key_material_copy(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_KM_REGISTER:
        result = dsec_ta_key_material_register(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_KM_GENERATE:
        result = dsec_ta_key_material_generate(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_KM_RETURN:
        result = dsec_ta_key_material_return(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_KM_DELETE:
        result = dsec_ta_key_material_delete(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_KM_SERIALIZE:
        result = dsec_ta_key_material_serialize(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_KM_DESERIALIZE:
        result = dsec_ta_key_material_deserialize(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_SESSION_KEY_CREATE_AND_GET:
        result = dsec_ta_session_key_create_and_get(parameters_type,
                                                    parameters);

        break;
    case DSEC_TA_CMD_AES_ENCRYPT:
        result = dsec_ta_aes_encrypt(parameters_type, parameters);
        break;

#if DSEC_TEST
    case DSEC_TA_CMD_SHA256:
        result = dsec_ta_test_sha256(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_LOAD_OBJECT_BUILTIN:
        result = dsec_ta_test_load_object_builtin(parameters_type, parameters);
        break;
    case DSEC_TA_CMD_UNLOAD_OBJECT:
        result = dsec_ta_test_unload_object();
        break;
    case DSEC_TA_CMD_HMAC_TESTS:
        result = dsec_ta_hmac_256_test(parameters_type, parameters);
        break;
#endif /* DSEC_TEST */
    default:
        DMSG("Invalid command identifier");
        result = TEE_ERROR_BAD_PARAMETERS;
        break;
    }

    return result;
}
