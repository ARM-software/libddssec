/*
 * DDS Security library
 * Copyright (c) 2018-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DSEC_TA_H
#define DSEC_TA_H

/*!
 * \addtogroup GroupTA Trusted Application
 * \{
 */

#ifndef DSEC_TA_UUID
    #error "DSEC_TA_UUID not defined"
#endif /* DSEC_TA_UUID */

/*!
 * \brief ID of callable TA functions
 */
enum {
    /*! Function ID of dsec_ta_ih_create */
    DSEC_TA_CMD_IH_CREATE,
    /*! Function ID of dsec_ta_ih_delete */
    DSEC_TA_CMD_IH_DELETE,
    /*! Function ID of dsec_ta_ih_get_info */
    DSEC_TA_CMD_IH_INFO,
    /*! Function ID of dsec_ta_ih_ca_load */
    DSEC_TA_CMD_IH_CA_LOAD,
    /*! Function ID of dsec_ta_ih_ca_unload */
    DSEC_TA_CMD_IH_CA_UNLOAD,
    /*! Function ID of dsec_ta_ih_ca_get_sn */
    DSEC_TA_CMD_IH_CA_GET_SN,
    /*! Function ID of dsec_ta_ih_ca_get_signature_algorithm */
    DSEC_TA_CMD_IH_CA_GET_SIGNATURE_ALGORITHM,
    /*! Function ID of dsec_ta_ih_cert_load */
    DSEC_TA_CMD_IH_CERT_LOAD,
    /*! Function ID of dsec_ta_ih_cert_unload */
    DSEC_TA_CMD_IH_CERT_UNLOAD,
    /*! Function ID of dsec_ta_ih_cert_get */
    DSEC_TA_CMD_IH_CERT_GET,
    /*! Function ID of dsec_ta_ih_cert_get_sn */
    DSEC_TA_CMD_IH_CERT_GET_SN,
    /*! Function ID of dsec_ta_ih_cert_get_signature */
    DSEC_TA_CMD_IH_CERT_GET_SIGNATURE_ALGORITHM,
    /*! Function ID of dsec_ta_ih_cert_load_from_buffer */
    DSEC_TA_CMD_IH_CERT_LOAD_FROM_BUFFER,
    /*! Function ID of dsec_ta_ih_cert_get_sha256_sn */
    DSEC_TA_CMD_IH_CERT_GET_SHA256_SN,
    /*! Function ID of dsec_ta_ih_cert_get_raw_sn */
    DSEC_TA_CMD_IH_CERT_GET_RAW_SN,
    /*! Function ID of dsec_ta_ih_privkey_load */
    DSEC_TA_CMD_IH_PRIVKEY_LOAD,
    /*! Function ID of dsec_ta_ih_privkey_unload */
    DSEC_TA_CMD_IH_PRIVKEY_UNLOAD,
    /*! Function ID of dsec_ta_ih_cert_signature_verify */
    DSEC_TA_CMD_IH_CERT_VERIFY,
    /*! Function ID of dsec_ta_ih_privkey_sign */
    DSEC_TA_CMD_IH_PRIVKEY_SIGN,
    /*! Function ID of dsec_ta_hh_create */
    DSEC_TA_CMD_HH_CREATE,
    /*! Function ID of dsec_ta_hh_delete */
    DSEC_TA_CMD_HH_DELETE,
    /*! Function ID of dsec_ta_hh_get_info */
    DSEC_TA_CMD_HH_INFO,
    /*! Function ID of dsec_ta_hh_dh_generate_keys */
    DSEC_TA_CMD_HH_DH_GENERATE_KEYS,
    /*! Function ID of dsec_ta_hh_dh_get_public */
    DSEC_TA_CMD_HH_DH_GET_PUBLIC,
    /*! Function ID of dsec_ta_hh_dh_unload */
    DSEC_TA_CMD_HH_DH_UNLOAD,
    /*! Function ID of dsec_ta_hh_dh_set_public */
    DSEC_TA_CMD_HH_DH_SET_PUBLIC,
    /*! Function ID of dsec_ta_hh_ssh_derive */
    DSEC_TA_CMD_SSH_DERIVE,
    /*! Function ID of dsec_ta_hh_challenge_generate */
    DSEC_TA_CMD_HH_CHALLENGE_GENERATE,
    /*! Function ID of dsec_ta_hh_challenge_get */
    DSEC_TA_CMD_HH_CHALLENGE_GET,
    /*! Function ID of dsec_ta_hh_challenge_set */
    DSEC_TA_CMD_HH_CHALLENGE_SET,
    /*! Function ID of dsec_ta_hh_challenge_unload */
    DSEC_TA_CMD_HH_CHALLENGE_UNLOAD,
    /*! Function ID of dsec_ta_ssh_get_data */
    DSEC_TA_CMD_SSH_GET_DATA,
    /*! Function ID of dsec_ta_ssh_unload */
    DSEC_TA_CMD_SSH_DELETE,
    /*! Function ID of dsec_ta_ssh_get_info */
    DSEC_TA_CMD_SSH_INFO,
    /*! Function ID of dsec_ta_key_material_create */
    DSEC_TA_CMD_KM_CREATE,
    /*! Function ID of dsec_ta_key_material_copy */
    DSEC_TA_CMD_KM_COPY,
    /*! Function ID of dsec_ta_key_material_register */
    DSEC_TA_CMD_KM_REGISTER,
    /*! Function ID of dsec_ta_key_material_generate */
    DSEC_TA_CMD_KM_GENERATE,
    /*! Function ID of dsec_ta_key_material_return */
    DSEC_TA_CMD_KM_RETURN,
    /*! Function ID of dsec_ta_key_material_delete */
    DSEC_TA_CMD_KM_DELETE,
    /*! Function ID of dsec_ta_key_material_serialize */
    DSEC_TA_CMD_KM_SERIALIZE,
    /*! Function ID of dsec_ta_key_material_deserialize */
    DSEC_TA_CMD_KM_DESERIALIZE,
    /*! Function ID of dsec_ta_key_material_remove_sender_key_id */
    DSEC_TA_CMD_KM_REMOVE_SENDER_KEY_ID,
    /*! Function ID of dsec_ta_session_key_create_and_get */
    DSEC_TA_CMD_SESSION_KEY_CREATE_AND_GET,
    /*! Function ID of dsec_ta_aes_encrypt */
    DSEC_TA_CMD_AES_ENCRYPT,
    /*! Function ID of dsec_ta_aes_decrypt */
    DSEC_TA_CMD_AES_DECRYPT,
    /*! Function ID of dsec_ta_aes_get_mac */
    DSEC_TA_CMD_AES_GET_MAC,
    /*! Function ID of dsec_ta_session_key_create */
    DSEC_TA_CMD_SESSION_KEY_CREATE,
    /*! Function ID of dsec_ta_session_key_encrypt */
    DSEC_TA_CMD_SESSION_KEY_ENCRYPT,
    /*! Function ID of dsec_ta_session_key_decrypt */
    DSEC_TA_CMD_SESSION_KEY_DECRYPT,
    /*! Function ID of dsec_ta_session_key_delete */
    DSEC_TA_CMD_SESSION_KEY_DELETE,
#if DSEC_TEST
    /*! Function ID of dsec_ta_test_sha256 */
    DSEC_TA_CMD_SHA256,
    /*! Function ID for dsec_ta_test_load_object_builtin */
    DSEC_TA_CMD_LOAD_OBJECT_BUILTIN,
    /*! Function ID for dsec_ta_test_load_object_storage */
    DSEC_TA_CMD_LOAD_OBJECT_STORAGE,
    /*! Function ID for dsec_ta_test_unload_object */
    DSEC_TA_CMD_UNLOAD_OBJECT,
    /*! Function ID for dsec_ta_test_create_persistent_object */
    DSEC_TA_CMD_CREATE_PERSISTENT_OBJECT,
    /*! Function ID for dsec_ta_test_delete_persistent_object */
    DSEC_TA_CMD_DELETE_PERSISTENT_OBJECT,
    /*! Function ID for dsec_ta_hmac_256_test */
    DSEC_TA_CMD_HMAC_TESTS,
#endif /* DSEC_TEST */
};

/*!
 * \}
 */

#endif /* DSEC_TA_H */
