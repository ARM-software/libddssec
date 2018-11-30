#
# DDS Security library
# Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

CFG_TEE_TA_LOG_LEVEL ?= 4
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) \
    -DDSEC_PROJECT_VERSION=$(PROJECT_VERSION) \
    -DDSEC_PROJECT_DESCRIPTION_SUMMARY="\"$(PROJECT_DESCRIPTION_SUMMARY)"\"

# The UUID for the trusted application (must match DSEC_TA_UUID)
BINARY=8ee919be-3954-4170-b4c2-da169f39536e

ifeq ($(TA_DEV_KIT_DIR),)
    $(error "TA_DEV_KIT_DIR not set. Aborting...")
endif

$(info Using TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR))

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
    $(error "TA_DEV_KIT_DIR is an invalid directory. Aborting...")
endif

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
