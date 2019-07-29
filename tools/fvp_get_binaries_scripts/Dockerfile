#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

FROM multiarch/alpine:aarch64-latest-stable AS bootstrap

FROM arm64v8/ubuntu:xenial AS sysroot

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
    make \
    gcc \
    python \
    python-crypto \
    lcov && \
    rm -rf /var/lib/apt/lists/*

# Update tty
RUN echo $'[Unit]\n\
Description=getty on ${TTY_NAME_CONSOLE} if dbus and logind are not available\n\
ConditionPathExists=/dev/${TTY_NAME_CONSOLE}\n\
ConditionPathExists=!/lib/systemd/system/dbus.service\n\
\n\
[Service]\n\
Type=oneshot\n\
ExecStart=/bin/systemctl --no-block start getty@${TTY_NAME_CONSOLE}.service\n\
RemainAfterExit=true'\
> /lib/systemd/system/getty.target.wants/getty-static.service

RUN ln -s /lib/systemd/system/getty@.service \
      /etc/systemd/system/getty.target.wants/getty@${TTY_NAME_CONSOLE}.service

RUN sed -i -e "s/DefaultInstance=tty1/DefaultInstance=${TTY_NAME_CONSOLE}/g" \
      /lib/systemd/system/getty@.service \
      /var/lib/dpkg/info/systemd.postinst \
      /var/lib/dpkg/info/systemd.postrm

# Enable root to log on the corresponding tty
RUN echo "${TTY_NAME_CONSOLE}" > /etc/securetty

# Create symlinks for the test frameworks
RUN ln -s /run/lib/optee-armtz /lib/optee-armtz && \
    mkdir -p /data && \
    ln -s /run/data /data
