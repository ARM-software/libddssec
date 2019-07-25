#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Include directories used by the TA
global-incdirs-y += \
    ../include \
    ../../include/libddssec

# Source files to build the TA
srcs-y += \
    dsec_ta.c \
    dsec_ta_digest.c \
    dsec_ta_manage_object.c \
    dsec_ta_ih.c \
    dsec_ta_ih_ca.c \
    dsec_ta_ih_cert.c \
    dsec_ta_ih_privkey.c \
    dsec_ta_hh.c \
    dsec_ta_dh.c \
    dsec_ta_ssh.c \
    dsec_ta_challenge.c \
    dsec_ta_hmac.c
