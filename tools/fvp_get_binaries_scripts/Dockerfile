#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

FROM multiarch/alpine:aarch64-latest-stable AS bootstrap

FROM arm64v8/ubuntu:bionic AS sysroot

COPY --from=bootstrap /usr/bin/qemu-aarch64-static /usr/bin/

ARG TTY_NAME_CONSOLE=ttyAMA0

RUN echo root:1234 | chpasswd

# Set timezone
RUN echo 'Etc/UTC' > /etc/timezone && \
    apt-get update && \
    apt-get install -q -y tzdata && \
    rm -rf /var/lib/apt/lists/* && \
    dpkg-reconfigure -f noninteractive tzdata

# Setup network
RUN echo "127.0.0.1   localhost" > /etc/hosts && \
    echo "nameserver 8.8.8.8" >  /etc/resolv.conf && \
    echo "nameserver 8.8.4.4" >> /etc/resolv.conf

# Get packages for compilation/tests
RUN apt-get update && apt-get install -y \
    cmake \
    lcov \
    libssl-dev \
    make \
    gcc \
    python \
    python3 \
    python-crypto \
    systemd && \
    rm -rf /var/lib/apt/lists/*

# Update tty
RUN systemctl enable getty@${TTY_NAME_CONSOLE}

# Enable root to log on the corresponding tty
RUN echo "${TTY_NAME_CONSOLE}" > /etc/securetty

# Create symlinks for the test frameworks
RUN rm -f /lib/optee_armtz && \
    mkdir -p /dev/shm/lib/optee_armtz && \
    ln -s /dev/shm/lib/optee_armtz /lib/optee_armtz && \
    rm -f /data && \
    mkdir -p /dev/shm/data && \
    ln -s /dev/shm/data /data
