/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
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
#if DSEC_TEST
    /*! Function ID for dsec_ta_test_load_object_builtin */
    DSEC_TA_CMD_LOAD_OBJECT_BUILTIN,
    /*! Function ID for dsec_ta_test_unload_object */
    DSEC_TA_CMD_UNLOAD_OBJECT,
#endif /* DSEC_TEST */
};

/*!
 * \}
 */

#endif /* DSEC_TA_H */
