/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_print.h>
#include <dsec_ca.h>
#include <dsec_ta.h>
#include <tee_client_api.h>

/*
 * Checks the parameters to a TA function to avoid dereferencing NULL memory in
 * OP-TEE client. Passing NULL and a non-zero size to TEEC_InvokeCommand causes
 * the OP-TEE client to fault while attempting to access invalid memory and
 * stop responding to the Normal World program.
 */
static TEEC_Result check_parameters(const TEEC_Operation* operation)
{
    int32_t result = 0;

    if (operation != NULL) {
        result = TEEC_SUCCESS;
        for (size_t i = (size_t)0;
             i < (size_t)TEEC_CONFIG_PAYLOAD_REF_COUNT;
             i++) {

            uint32_t parameter =
                TEEC_PARAM_TYPE_GET((operation->paramTypes), i);
            switch (parameter) {

            case TEEC_MEMREF_TEMP_INPUT:
                /* Falls through */
            case TEEC_MEMREF_TEMP_OUTPUT:
                /* Falls through */
            case TEEC_MEMREF_TEMP_INOUT:
                if ((operation->params[i].tmpref.buffer == NULL) &&
                    (operation->params[i].tmpref.size > 0U)) {

                    dsec_print("NULL buffer with size larger than zero\n");
                    result = TEEC_ERROR_BAD_PARAMETERS;
                }
                break;
            case TEEC_MEMREF_WHOLE:
                /* Falls through */
            case TEEC_MEMREF_PARTIAL_INPUT:
                /* Falls through */
            case TEEC_MEMREF_PARTIAL_OUTPUT:
                /* Falls through */
            case TEEC_MEMREF_PARTIAL_INOUT:
                if ((operation->params[i].memref.parent == NULL) &&
                    (operation->params[i].memref.size > 0U)) {

                    dsec_print("NULL buffer with size larger than zero\n");
                    result = TEEC_ERROR_BAD_PARAMETERS;
                }

                /*
                 * At the time of writing, these types should not be necessary,
                 * hence the redundant error. If these types become necessary,
                 * the above checks should be kept to prevent the program from
                 * becoming non-responsive when passed a NULL parent and
                 * non-zero size
                 */
                result = TEEC_ERROR_BAD_PARAMETERS;
                break;
            case TEEC_NONE:
            case TEEC_VALUE_INPUT:
            case TEEC_VALUE_OUTPUT:
            case TEEC_VALUE_INOUT:
                /* No error */
                break;
            default:
                dsec_print("Invalid parameter type\n");
                result = TEEC_ERROR_BAD_PARAMETERS;
                break;
            }
        }
    } else {
        dsec_print("Null operation\n");
        result = TEEC_ERROR_BAD_PARAMETERS;
    }

    return result;
}

/* Checks that the instance is open and has a valid context and session */
static int32_t check_instance(const struct dsec_instance* instance,
                              bool status)
{
    int32_t result = 0;
    if (instance != NULL) {
        if (instance->open == status) {
            if (instance->context != NULL) {
                if (instance->session != NULL) {
                    result = DSEC_SUCCESS;
                } else {
                    dsec_print("Instance session is NULL\n");
                    result = DSEC_E_PARAM;
                }
            } else {
                dsec_print("Instance context is NULL\n");
                result = DSEC_E_PARAM;
            }
        } else {
            dsec_print("Instance in wrong state\n");
            result = DSEC_E_INIT;
        }
    } else {
        dsec_print("Instance is NULL\n");
        result = DSEC_E_PARAM;
    }

    return result;
}

struct dsec_instance dsec_ca_instance_create(TEEC_Session* session,
                                             TEEC_Context* context)
{
    struct dsec_instance instance = {
        .context = context,
        .session = session,
        .open = false
    };
    return instance;
}

int32_t dsec_ca_instance_open(struct dsec_instance* instance)
{
    TEEC_UUID uuid = DSEC_TA_UUID;
    uint32_t origin;
    int32_t result = check_instance(instance, false);
    TEEC_Result teec_result = 0;

    if (result == DSEC_SUCCESS) {
        teec_result = TEEC_InitializeContext(NULL, instance->context);

        if (teec_result == TEEC_SUCCESS) {

            teec_result = TEEC_OpenSession(instance->context,
                                           instance->session,
                                           &uuid,
                                           TEEC_LOGIN_PUBLIC,
                                           NULL,
                                           NULL,
                                           &origin);

            if (teec_result == TEEC_SUCCESS) {
                instance->open = true;
                result = DSEC_SUCCESS;
            } else {
                dsec_print("Can't open a session. Error: 0x%X Origin: %x\n",
                           teec_result,
                           origin);
                TEEC_FinalizeContext(instance->context);
                result = DSEC_E_INIT;
            }
        } else {
            dsec_print("Can't initialize a context. Error: 0x%X\n",
                       teec_result);

            result = DSEC_E_INIT;
        }
    }

    return result;
}

int32_t dsec_ca_instance_close(struct dsec_instance* instance)
{
    int32_t result = check_instance(instance, true /* is open */);

    if (result == DSEC_SUCCESS) {
        TEEC_CloseSession(instance->session);
        instance->session = NULL;
        TEEC_FinalizeContext(instance->context);
        instance->context = NULL;
        instance->open = false;
    }

    return result;
}

int32_t dsec_ca_convert_teec_result(TEEC_Result teec_result)
{
    int32_t result = 0;

    switch (teec_result) {
    case TEEC_SUCCESS:
        result = DSEC_SUCCESS;
        break;
    case TEEC_ERROR_BAD_PARAMETERS:
        result = DSEC_E_PARAM;
        break;
    case TEEC_ERROR_ITEM_NOT_FOUND:
        result = DSEC_E_NOT_FOUND;
        break;
    case TEEC_ERROR_BAD_FORMAT:
        result = DSEC_E_BAD_FORMAT;
        break;
    case TEEC_ERROR_OUT_OF_MEMORY:
        result = DSEC_E_MEMORY;
        break;
    case TEEC_ERROR_SECURITY:
        result = DSEC_E_SECURITY;
        break;
    case TEEC_ERROR_NO_DATA:
        result = DSEC_E_DATA;
        break;
    case TEEC_ERROR_SHORT_BUFFER:
        result = DSEC_E_SHORT_BUFFER;
        break;
    default:
        result = DSEC_E_TEE;
    }

    dsec_print("TEEC_Result 0x%x converted to dsec error code 0x%x\n",
               teec_result,
               result);

    return result;
}

TEEC_Result dsec_ca_invoke(const struct dsec_instance* instance,
                           uint32_t command_id,
                           TEEC_Operation* operation,
                           uint32_t* origin)
{

    TEEC_Result result = check_instance(instance, true /* is open */);
    if (result == DSEC_SUCCESS) {
        /* Passing invalid memory as a parameter will crash the program */
        result = check_parameters(operation);
        if (result == DSEC_SUCCESS) {
            result = TEEC_InvokeCommand(instance->session,
                                        (uint32_t)command_id,
                                        operation,
                                        origin);
        } else {
            dsec_print("Invalid parameters\n");
        }
    } else {
        dsec_print("Invalid instance\n");
    }

    return result;
}
