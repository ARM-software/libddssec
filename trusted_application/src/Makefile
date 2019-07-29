#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

ifndef $(DSEC_TEST)
    DSEC_TEST = 0
endif

CFG_TEE_TA_LOG_LEVEL ?= 4
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) \
    -DDSEC_PROJECT_VERSION=$(PROJECT_VERSION) \
    -DDSEC_PROJECT_DESCRIPTION_SUMMARY="\"$(PROJECT_DESCRIPTION_SUMMARY)"\" \
    -DDSEC_TA_UUID="$(DSEC_TA_UUID)" \
    -DDSEC_TA_UUID_STRING=$(DSEC_TA_UUID_STRING) \
    -DDSEC_TEST=$(DSEC_TEST) \
    -Wall \
    -Wextra \
    -Werror \
    -Wno-missing-field-initializers \
    -Wno-unused-parameter \
    -Wfloat-equal \
    -Wformat-security \
    -Wformat-nonliteral \
    -Wformat-y2k \
    -Wmissing-declarations \
    -Wmissing-include-dirs \
    -Wmissing-noreturn \
    -Wnested-externs \
    -Wshadow \
    -Wstrict-prototypes \
    -Wswitch-default \
    -pedantic \
    -pedantic-errors \
    -fstack-protector-all \
    -fpie

# The UUID for the trusted application (must match DSEC_TA_UUID)
BINARY=$(DSEC_TA_UUID_STRING)

ifeq ($(TA_DEV_KIT_DIR),)
    $(error "TA_DEV_KIT_DIR not set. Aborting...")
endif

$(info Using TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR))

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
    $(error "TA_DEV_KIT_DIR is an invalid directory. Aborting...")
endif

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
