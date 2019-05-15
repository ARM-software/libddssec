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
