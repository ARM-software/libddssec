/*
 * DDS Security library
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>
#include <dsec_test_ta.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Constants to be set from the test build system */

/* The full source path of the TA to be used for the test */
#ifndef DSEC_TA_LOCATION
    #error "DSEC_TA_LOCATION not defined"
#endif
/* The full destination path of the TA to be used for the test */
#ifndef DSEC_TA_DESTINATION
    #error "DSEC_TA_DESTINATION not defined"
#endif
/* The destination directory of the TA to be used for the test */
#ifndef DSEC_TA_DESTINATION_DIR
    #error "DSEC_TA_DESTINATION_DIR not defined"
#endif

/* Set to true if the TA already existed */
static bool ta_existed;
/* Set to true if the TA directory already existed */
static bool armtz_existed;

static int shell(const char *fmt, ...)
{
    const int DSEC_MAX_COMMAND_SIZE = 4096;
    char command[DSEC_MAX_COMMAND_SIZE];
    va_list args;
    int retval;

    va_start(args, fmt);
    retval = vsnprintf(command, DSEC_MAX_COMMAND_SIZE, fmt, args);
    va_end(args);

    if (retval < 0) {
        fprintf(stderr, "Error trying to build up command string\n");
        return DSEC_E_DATA;
    }

    if (retval >= DSEC_MAX_COMMAND_SIZE) {
        fprintf(stderr,
            "Command string will be truncated because it is too long\n");
        return DSEC_E_DATA;
    }

    retval = system(command);
    if (retval == -1) {
        fprintf(stderr, "Failed to invoke the command:\n%s", command);
        return DSEC_E_DATA;
    }

    return WEXITSTATUS(retval);
}

int dsec_test_ta_setup(void)
{
    armtz_existed = false;
    int command_retval = DSEC_E_INIT;

    if (access(DSEC_TA_DESTINATION, R_OK) != -1) {
        ta_existed = true;

        /* mv {TA_DIR}/{UUID}.ta {TA_DIR}/{UUID}.ta.bak */
        command_retval = shell("mv %s %s.bak 2>/dev/null",
            DSEC_TA_DESTINATION,
            DSEC_TA_DESTINATION);

        if (command_retval) {
            fprintf(stderr,
                "Existing TA at %s could not be backed up to %s.bak\n",
                DSEC_TA_DESTINATION,
                DSEC_TA_DESTINATION);
            return DSEC_E_ACCESS;
        }
    }

    /* Creates a directory with read/write/execute permissions for all users */
    if (mkdir(DSEC_TA_DESTINATION_DIR, 0777)) {

        switch (errno) {
        /*
         * Directory already exists. Continue but don't delete the directory at
         * the end.
         */
        case EEXIST:
            armtz_existed = true;
            break;

        case ENOTDIR:
            perror("Could not create TA directory");
            return DSEC_E_DATA;
        case EACCES:
            perror("Could not create TA directory");
            return DSEC_E_ACCESS;
        default:
            perror("Could not create TA directory");
            return DSEC_E_SUPPORT;
        }
    }

    /* cp {DSEC_TA_UUID}.ta DSEC_TA_DESTINATION */
    command_retval = shell("cp %s %s",
        DSEC_TA_LOCATION,
        DSEC_TA_DESTINATION_DIR);

    if (command_retval) {
        fprintf(stderr, "Could not copy the TA from %s to %s.\n",
            DSEC_TA_LOCATION,
            DSEC_TA_DESTINATION_DIR);

        fprintf(stderr, "Error is: %d.\n", command_retval);
        fprintf(stderr, "Are you root?\n");
        return DSEC_E_SUPPORT;
    }

    command_retval = shell("which tee-supplicant > /dev/null");
    if (command_retval) {
        fprintf(stderr, "tee-supplicant not found.\n");
        return DSEC_E_ACCESS;
    }

    /* Launch tee-supplicant daemon */
    command_retval = shell("tee-supplicant &");
    if (command_retval) {
        fprintf(stderr,
            "tee-supplicant was found but could not be launched.\n");
        return DSEC_E_PARAM;
    }

    return DSEC_SUCCESS;
}

int dsec_test_ta_teardown(void)
{
    int command_retval = DSEC_E_INIT;

    /* Kill tee-supplicant daemon */
    command_retval = shell("pkill tee-supplicant");
    if (command_retval) {
        fprintf(stderr, "tee-supplicant could not be killed.\n");
        /* Not fatal, continue */
    }

    /* Remove TA file */
    command_retval = shell("rm -I %s", DSEC_TA_DESTINATION);
    if (command_retval != EXIT_SUCCESS) {
        /* The error codes for rm are not specific */
        return DSEC_E_ACCESS;
    }

    if (!armtz_existed) {
        /* Remove TA directory */
        command_retval = shell("rm -d %s", DSEC_TA_DESTINATION_DIR);
        if (command_retval != EXIT_SUCCESS) {
            /* The error codes for rm are not specific */
            return DSEC_E_ACCESS;
        }
    } else if (ta_existed) {
        /* Restore old TA backed up */
        /* mv {DSEC_TA_DESTINATION}.bak {DSEC_TA_DESTINATION} */
        command_retval = shell("mv %s.bak %s 2>/dev/null",
            DSEC_TA_DESTINATION,
            DSEC_TA_DESTINATION);

        if (command_retval) {
            fprintf(stderr,
                "TA backup at %s.bak could not be moved back to %s\n",
                DSEC_TA_DESTINATION,
                DSEC_TA_DESTINATION);
            /* Not fatal, continue */
        }
    }

    return DSEC_SUCCESS;
}
