/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ssh.h
 * Source code for handling shared secrets.
 */

#ifndef DSEC_SSH_H
#define DSEC_SSH_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * \defgroup GroupSharedSecretHandle Function for Shared Secret Handle
 *     management.
 * \{
 */

#include <dsec_ca.h>
#include <stdint.h>

/*!
 * \brief Derive a shared secret
 *
 * \details Calls the Trusted Application to derive a shared secret from the
 *     information stored in the Handshake Handle specified.
 *
 * \param[out] ssh_id Handle ID of the shared secret.
 *
 * \param instance Initialized instance to access the Trusted Application
 * \param hh_id Handle ID of the Handshake Handle.
 *
 * \retval ::DSEC_SUCCESS Shared secret has been generated.
 * \return TEE_Result from the function DSEC_TA_CMD_SSH_DERIVE invoked in the TA
 *     converted to a DSEC_E_
 */
int32_t dsec_ssh_derive(int32_t* ssh_id,
                        const struct dsec_instance* instance,
                        int32_t hh_id);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_SSH_H */
