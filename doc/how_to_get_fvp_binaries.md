# Fast-Model
This document provides guidelines to setup a virtual platform for testing
libddssec.

## Get the Model

This library makes use of the `Armv8-A Base Platform FVP` for the tests and
development. It is used to run Ubuntu based on Linux with Arm Trusted Firmware A
and with OP-TEE OS.

Download `Armv8-A Base Platform FVP based on Fast Models` from [here](https://developer.arm.com/tools-and-software/simulation-models/fixed-virtual-platforms).

After untar-ing, the model binary can be found under the following directory:
`Base_RevC_AEMv8A_pkg/models/Linux64_GCC-4.9`.

More info about the AEMv8A platform can be found here:
http://arminfo.emea.arm.com/help/topic/com.arm.doc.subset.models.vplatforms/index.html

## Get the binaries

In order to get the necessary files to test the library, you will need to
install Docker (https://docs.docker.com/). The Docker image to build the Ubuntu
file-system needs `alpine` (https://github.com/multiarch/alpine). This means
that the Docker host must have the `binfmt-support` configured.
All the scripts described bellow are under `../tools/fvp_get_binaries_scripts/`.
At the end of those steps, the folder `arm_platform_build/uboot` will contain
all the necessary files to start the tests on FVP.

### BSP

Arm provides a reference software stack gathering all the binaries for running
Linux on FVP. See [reference software stack](https://developer.arm.com/tools-and-software/open-source-software/arm-platforms-software/cortex-a-platforms-software).

As the process requires different steps, they are automated through the Docker
file `Dockerfile_binaries`. The script `build_binaries.sh` will produce the
folder `arm_platform_build`:
- uboot: contains the necessary files for booting the FVP up-to Linux.
- optee: contains OP-TEE Client and OP-TEE OS.
- `gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu`: toolchain for aarch64.
  This toolchain can be used for building the library.

This script takes some time to gather and build all the different repositories.

### Build Ubuntu filesytem

The script `build_ubuntu_image.sh` invokes Docker with the Dockerfile
`Dockerfile` to build the Ubuntu filesystem. It requires the path to OP-TEE OS
and OP-TEE Client which is already set to the output of the previous script
(see variables `ARM_PLATFORM_OUTPUT_PATH`,`OPTEE_OS_DIR` and
`OPTEE_CLIENT_DIR`). In order to produce the `.img`, the script will need `sudo`
permission to mount the image. The image produced is located at
`UBUNTU_IMAGE_DIR` which by default is under `arm_platform_build/uboot`.

## Launching validate.py

The following command should be enough to launch the tests. Assuming the path
to the FVP binary `FVP_Base_RevC-2xAEMv8A` is set in the environment variable.

```bash
ARM_PLATFORM_PATH=`pwd`/tools/fvp_get_binaries_scripts/arm_platform_build
TARGET_ARCH=aarch64 \
CROSS_COMPILE=$ARM_PLATFORM_PATH/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu- \
OPTEECLIENT_DIR=$ARM_PLATFORM_PATH/optee/optee_client \
TA_DEV_KIT_DIR=$ARM_PLATFORM_PATH/optee/optee_os/out/arm-plat-vexpress/export-ta_arm64 \
tools/validate.py --test-fvp $ARM_PLATFORM_PATH/uboot
```
