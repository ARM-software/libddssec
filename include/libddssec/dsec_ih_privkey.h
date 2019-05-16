/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * @file dsec_ih_privkey.h
 * Source code for handling private keys.
 */

#ifndef DSEC_IH_PRIVKEY_H
#define DSEC_IH_PRIVKEY_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * \addtogroup GroupIdentityHandle
 *
 * Function for managing a Private Key inside an Identity Handle.
 * \{
 */

#include <dsec_ih.h>
#include <stdint.h>

/*!
 * \brief Maximum size of a filename to describe a path to a Private Key.
 */
#define DSEC_IH_PRIVKEY_MAX_FILENAME (2048UL)

/*
 * Extra care is taken here to make sure the maximum size of the filename
 * cannot exceed UINT32_MAX. This is because OPTEE-OS parameters are uint32_t.
 */
#if (DSEC_IH_PRIVKEY_MAX_FILENAME > UINT32_MAX)
#error "DSEC_IH_PRIVKEY_MAX_FILENAME cannot be more than UINT32_MAX"
#endif

/*!
 * \brief Load a Private Key from file name.
 *
 * \details Calls the Trusted Application to load a Private Key for a specific
 *     Identity Handle ID.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param ih_id Handle ID of the Identity Handle.
 * \param filename Byte array NULL terminated containing the file name.
 * \param password Byte array NULL terminated containing the file name. Can be
 *     NULL if there is no password.
 * \param password_size Number of bytes contained by the buffer including the
 *     '\0' character. It cannot be 0 if password parameter is not NULL.
 *
 * \retval ::DSEC_SUCCESS Private key has been loaded.
 * \return TEE_Result from the function DSEC_TA_CMD_IH_PRIVKEY_LOAD invoked in
 *     the TA converted to a DSEC_E_
 */
int32_t dsec_ih_privkey_load(const struct dsec_instance* instance,
                             int32_t ih_id,
                             const char* filename,
                             const char* password,
                             uint32_t password_size);

/*!
 * \brief Unload a Private Key of an Identity Handle.
 *
 * \details Calls the Trusted Application to unload a Private Key for a specific
 *     Identity Handle ID.
 *
 * \param instance Initialized instance to access the Trusted Application.
 * \param ih_id Handle ID of the Identity Handle.
 *
 * \retval ::DSEC_SUCCESS Private Key has been unloaded.
 * \return TEE_Result from the function DSEC_TA_CMD_IH_PRIVKEY_UNLOAD invoked in
 *     the TA converted to a DSEC_E_
 */
int32_t dsec_ih_privkey_unload(const struct dsec_instance* instance,
                               int32_t ih_id);

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DSEC_IH_PRIVKEY_H */
