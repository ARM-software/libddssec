#!/usr/bin/env bash
#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Use Docker with qemu to create an Arm-based Ubuntu filesystem and produce a
# .img with two partitions to be used with an FVP.

set -e

# Go to the folder where the script is
SCRIPT_LOCATION_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "${SCRIPT_LOCATION_PATH}"

SYSROOT_OUTPUT_NAME=sysroot_docker.tar
SYSTEM_NAME=aemv8
TTY_NAME_CONSOLE=ttyAMA0
ARM_PLATFORM_OUTPUT_PATH=`pwd`/arm_platform_build
OPTEE_OS_DIR=$ARM_PLATFORM_OUTPUT_PATH/optee/optee_os
OPTEE_CLIENT_DIR=$ARM_PLATFORM_OUTPUT_PATH/optee/optee_client
UBUNTU_IMAGE_DIR=$ARM_PLATFORM_OUTPUT_PATH/uboot/

# Creates an image from a given tar archive.
# The image has 2 partitions.
create_img() {
    sysroot="$1"
    image_name="$2"
    mount_folder=mount_loop

    # If exist, remove the old image
    [ -e $image_name ] && rm -f $image_name

    # Create a 2GB image
    dd if=/dev/zero of="$image_name" bs=1M count=1 seek=2049

    sudo mkdir -p $mount_folder
    # Create two partitions:
    # vda1 (unused) of 1MB
    # vda2 (Ubuntu) of 2048MB
    # Demangled commands: n p 1 <\n> 4095 n p 2 <\n> <\n> w q
    echo -e "n\np\n1\n\n4095\nn\np\n2\n\n\nw\nq\n" | fdisk "$image_name"
    dev_loop=`sudo partx -v -a "$image_name" | grep /dev/loop | tail -n 1`
    dev_loop_a=(${dev_loop//:/ })
    if [ -z "$dev_loop_a" ]; then
        echo "Error, cannot recover loop device $dev_loop_a"
        return -1
    fi

    # Create the filesystem type as ext4 for the second partition
    sudo mkfs.ext4 -F $dev_loop_a"p2"
    # Mount the partition to the folder mount_loop
    sudo mount -o loop $dev_loop_a"p2" ./$mount_folder/

    sudo tar -C $mount_folder -xf "$sysroot"

    sync

    sudo umount $mount_folder
    sudo rm -rf ./$mount_folder
    sudo partx -d -v $dev_loop_a
}

docker build --build-arg TTY_NAME_CONSOLE=$TTY_NAME_CONSOLE \
    -t aarch64:latest \
    -f ./Dockerfile .

CONTAINER_NAME=aarch64_sysroot

docker create --name aarch64_sysroot aarch64:latest

CONTAINER_ID=`docker ps -aqf "name=$CONTAINER_NAME"`

# Copy OP-TEE dependencies for build
docker cp $OPTEE_OS_DIR/out/arm-plat-vexpress/export-ta_arm64/. \
          $CONTAINER_ID:/root/ta_dev_kit/

docker cp $OPTEE_CLIENT_DIR $CONTAINER_ID:/root/

# Copy libraries and binaries for execution dependencies
docker cp $OPTEE_CLIENT_DIR/out/export/bin/tee-supplicant \
          $CONTAINER_ID:/bin/

docker cp $OPTEE_CLIENT_DIR/out/export/lib/. $CONTAINER_ID:/lib/

# Export sysroot image
docker container export --output="$SYSROOT_OUTPUT_NAME" $CONTAINER_NAME
# Create the image
create_img "`pwd`/$SYSROOT_OUTPUT_NAME" "$UBUNTU_IMAGE_DIR/ubuntu.img"

# Remove docker container
docker rm $CONTAINER_NAME

# Remove sysroot tarball used to populate the final image
rm $SYSROOT_OUTPUT_NAME
