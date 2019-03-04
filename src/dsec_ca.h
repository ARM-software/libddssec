/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * \file
 * \brief \copybrief GroupClientApplication
 */

#ifndef DSEC_CA_H
#define DSEC_CA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <tee_client_api.h>
#include <stdbool.h>
#include <stdint.h>

/* Used to combine a TEE Client context and session for ease-of-use */
struct dsec_instance {
    TEEC_Context* context;
    TEEC_Session* session;
    /* Do not change the 'open' member directly */
    bool open;
};

/* Returns a new instance */
struct dsec_instance dsec_ca_instance_create(TEEC_Session* session,
                                             TEEC_Context* context);

/*
 * Opens the instance if it has not already been opened, then sets the
 * meta-data to say the instance is open
 */
int32_t dsec_ca_instance_open(struct dsec_instance* instance);

/*
 * Closes the instance if it is open, then sets the meta-data to say the
 * instance is closed
 */
int32_t dsec_ca_instance_close(struct dsec_instance* instance);

/*
 * Checks the parameters for safe values before calling TEEC_InvokeCommand to
 * invoke a function within the TA
 */
TEEC_Result dsec_ca_invoke(const struct dsec_instance* instance,
                           uint32_t command_id,
                           TEEC_Operation* operation,
                           uint32_t* origin);

#ifdef __cplusplus
}
#endif

#endif /* DSEC_CA_H */
