#!/usr/bin/env bash
#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Create a Docker that will build the Arm Platform stack.
# Extract the OPTEE-OS and OPTEE-Client binaries and libraries.
# Extract the output binaries for booting Linux on FVP.

set -e

# Go to the folder where the script is
SCRIPT_LOCATION_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "${SCRIPT_LOCATION_PATH}"

ARM_PLATFORM_OUTPUT_PATH=`pwd`/arm_platform_build
mkdir -p $ARM_PLATFORM_OUTPUT_PATH
rm -rf $ARM_PLATFORM_OUTPUT_PATH/./*

CONTAINER_NAME=ubuntu_arm_plat_build
DOCKER_TAG=ubuntu_arm_plat:bionic

docker pull ubuntu:bionic
docker build -t $DOCKER_TAG - < ./Dockerfile_binaries

docker run --name $CONTAINER_NAME $DOCKER_TAG
# Run the command below instead of the one above to have access to bash in the
# created container.
#docker run -it $DOCKER_TAG bash

# Extract the produced binaries
docker cp $CONTAINER_NAME:/shared_folder/output/fvp/fvp-oe/uboot \
       $ARM_PLATFORM_OUTPUT_PATH

# Extract the OP-TEE sources
docker cp $CONTAINER_NAME:/shared_folder/optee $ARM_PLATFORM_OUTPUT_PATH

# Remove dead symlink from the copy
rm -rf $ARM_PLATFORM_OUTPUT_PATH/optee/optee_client/.git
rm -rf $ARM_PLATFORM_OUTPUT_PATH/optee/optee_os/.git

# Extract the toolchain file for aarch64
TOOLCHAIN_PATH=tools/gcc/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu
docker cp $CONTAINER_NAME:/shared_folder/$TOOLCHAIN_PATH \
          $ARM_PLATFORM_OUTPUT_PATH

docker container rm $CONTAINER_NAME
