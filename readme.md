# Readme

Copyright (c) 2018-2020, Arm Limited. All rights reserved.



## Introduction

In an autonomous future where machines are continually interacting with humans,
ensuring the operational correctness of these machines is going to be of
paramount importance. These machines are going to be commonplace, and a target
for misuse, malware and hacking on a daily basis.

By only allowing trusted nodes to interact with decision making parts of the
system, we can ensure that the system will always operate as the manufacturer
intended. Rogue items can be detected, and any data generated from these devices
can be discounted as untrusted.

The DDS Security library (__libddssec__) is an open source software library that
provides security services for implementations of the [Data Distribution Service
(DDS) specification][1]. The main goal of the _libddssec_ is to offer a common
implementation of the security operations using Arm's [TrustZone IP][2]. This
implementation uses [OP-TEE][3] to isolate secure operations and assets under a
Trusted Execution Environment.

![The DDS implementation, starting in the Non-Trusted Environment, uses security plugins to call the libddssec API, existing in a domain called the libddssec CA. libddssec's TEEC_API functions back-end sends these requests to the OP-TEE Client Library (TEEC), which passes it on the TEE Kernel Driver over ioctl. The TEE Kernel Driver uses ioctl to communicate with the tee-supplicant, used to load information from the file-system including the encrypted data in /data/tee and the TA binary in /lib/optee_armtz. The TEE Kernel Driver also communicates with TF-A over Secure Monitor Call (SMC), entering the Trusted Environment. TF-A uses another SMC to communicate with OP-TEE OS (running in the Trusted Environment) which contains mbedTLS, libtomcrypt, and Secure Storage libraries. OP-TEE OS communicates with libddssec's dsec TA to access the assets needed for the DDS security plugins safely and without exposing them to the Non-Trusted Environment. Both environments can use shared memory, but this is not used in libddssec](doc/media/Big_picture.svg)

## Libddssec project goals

The goal of libddssec is to improve security implementations of DDS plugins for
Arm-based systems using the TrustZone IP. libddssec is a reference
implementation of the DDS specification's security plugins that uses the Trusted
Execution Environment (TEE) to store secure assets, aiming to keep them secure
even in a system where the normal world is compromised. This library is intended
to be used by DDS implementations as a way to integrate TEE based security into
their own library.

The following critical assets are intended to be stored in TrustZone

 - Private Keys: asymmetric key. Unique for a participant and injected before
   launching the application. In the final version of the library, private keys
   should be generated and a certificate signing request should be exported out
   to be signed by a CA and re-injected.

 - Session Keys: Generated after authentication and used for message exchange.
   Those keys are generated during run-time.

To prevent tampering of data, some non-critical assets are also stored in
TrustZone. These are public assets and are not considered as sensitive data

 - The public certificate of the Certificate Authority (CA): used to
   authenticate the different remote participant certificates signed previously.
   This certificate is not sent through the DDS protocol and only stays locally
   in the node for verifying a participant certificate (local and remote).
   Tampering will cause the participant (local/remote) to be unauthenticated as
   the CA certificate won’t authenticate the participant certificates.

 - The public certificate of the local participant: used to authenticate a
   participant. If this certificate is tampered with, the private key won't
   match, and the node won't communicate as it won't be able to sign a message
   using the private key.

 - Certificate revocation list (CRL): Stored within the CA Certificate to remove
   old or formerly trusted signed certificates which are no longer trusted (so
   have been revoked).

Apart from tampering, storing those certificates in a central location in the
TEE helps to avoid mixing libraries with incompatible formats.

For more details on the motivation for libddssec and how it works, read the
[About libddssec](doc/about_libddssec.md).

## Supported platforms

libddssec is developed and tested using Ubuntu 16.04.6 LTS on 64-bit Arm-based
systems (aarch64) with TrustZone support and OP-TEE enabled. The tests are run
using the [Armv8-A Base Platform FVP][4] using the [Arm Development Platforms
stack][5], both of which available free-of-charge.

While 32-bit builds may work, they should be considered untested.

## Prerequisites

To build __libddssec__, the following dependencies are required:

- CMake (3.5 or later)
- Gnu Make (4.1 or later)
- GCC (5.6 or later)
- Python (3.5 or later)
- [OP-TEE Client](https://github.com/OP-TEE/optee_client) (3.3 or later)

To build the trusted application, the following dependencies are required:

- [OP-TEE OS](https://github.com/OP-TEE/optee_os) (3.3 or later).

In addition, the following dependencies are recommended for validation:

- Doxygen (1.8.11 or later): Required to build supporting documentation.
- Dot (Graphviz 2.38 or later): Required to add diagrams in the documentation.
- checkpatch.pl (4.9 or later): Required by check_style.py.
- cmakelint (1.4 or later): Required by check_style_cmake.py.
- Pexpect: Used by validate.py to interact with remote devices.
- pycodestyle: Used by validate.py to check python script coding style.
- git

## Building the library and trusted application

The next steps show an overview on how to build libddssec. For more details on
how to integrate it in your project, please refer to the
[Using libddssec](doc/using_libddssec.md) documentation.

Create a directory for the build output:

    $> mkdir build

Enter the build directory and run ```cmake```:

    $> cd build

    $> # Native compilation
    $> cmake -DOPTEECLIENT_DIR=<path to OP-TEE Client> ..

    $> # Cross compilation
    $> export TARGET_ARCH=<aarch64 | arm>
    $> export CROSS_COMPILE=<cross-compiler path and prefix>
    $> cmake -DOPTEECLIENT_DIR=<path to OP-TEE Client> \
             -DCMAKE_TOOLCHAIN_FILE=../tools/toolchain.cmake \
             ..

To build the library, use ```make```:

    $> make

To build the trusted application, use the target ```ta```. Ensure the
TA_DEV_KIT_DIR environment variable points to the OP-TEE OS build targeting your
platform. You may also set CROSS_COMPILE according to your development
environment. Example:

    $> export TA_DEV_KIT_DIR=<path to optee_os build>/<platform>/export-ta_xxx
    $> export CROSS_COMPILE=<cross-compiler path and prefix>
    $> make ta

To clean the trusted application build, use the target ```ta-clean```:

    $> make ta-clean

## Verification

To build and run the unit tests on an Arm device:

    $> make build_and_test

Note: To enable the tests, the flag `BUILD_TEST` must be defined to `ON`
(`-DBUILD_TEST=ON`) when cmake is invoked.

The ```validation.py``` tool can be used during development to verify the code.
This tool will build and run the units as well check code style and
documentation.

To list available options:

    ./tools/validation.py --help

As most of the features require an Arm architecture, using this tool requires
an Arm target when building on another architecture. Additionally, the
invasiveness of the tests mean it is undesirable to run them natively. The
tools offers two possibilities to solve this:

 - Using ssh by specifying the IP address of the remote device
 - Using the [Armv8-A Base Platform FVP][4]

Whichever is chosen, the tool will tear-down any created files. For use in
systematic testing, however, a filesystem that is read-only or that is reset
between tests is advisable to avoid interference from unforeseen side-effects.

Using the fast-model option requires supplying a path to the binaries (the
filesystem, RAMdisks, et al.) and that the fast-model 'FVP_Base_RevC-2xAEMv8A'
is located in the PATH.

Using the tool to connect to a remote device:

    ./tools/validation.py --target-ssh <ip|hostname>[:port]

Using the tool to launch a model:

    ./tools/validation.py --target-fvp <path>

This path must include:

- bl1: 'bl1.bin'
- dtb: 'fvp-base-aemv8a-aemv8a.dtb'
- fip: 'fip.bin'
- Kernel: 'Image'
- Ramdisk: 'ramdisk.img'
- Filesystem: 'ubuntu.img'

Please follow the steps from [How to Get the FVP
Binaries](doc/how_to_get_fvp_binaries.md) for details on how to get the binaries
necessary for the tests using FVP.

In order to build and test libddssec and its trusted application natively, the
validation.py tool requires the target file system to have:

- OP-TEE Client installed (library and tee-supplicant) as well as a copy of the
source code in `$HOME/optee_client` which will be used to build and link
libddssec.
- A copy of the OP-TEE TA development kit in the `$HOME/ta_dev_kit directory`
which will be used to build libddssec's trusted application.

The test framework will copy all the sources and build scripts and compile
natively on the target platform. It will copy the Trusted Application to the
test platform and backup the old one, if it exists. Then, it will start
`tee-supplicant` and run the tests. During the tear-down process, the daemon
`tee-supplicant` is killed and all backed-up files are restored.

The tool also allows users to supply libddssec already pre-built speeding-up the
tests as the build will be skipped on the target (see the options
``--prebuild-path``).

## Documentation

If Doxygen is available on the system containing the __libddssec__ then
comprehensive documentation can be generated. The complete set of documentation
is compiled into a bundle in HTML format and placed in the *_build_/doc*
directory.

Note: To enable the documentation generation, the flag `BUILD_DOC` must be
defined to `ON` (`-DBUILD_DOC=ON`) when CMake is invoked.

After you create a build directory and run CMake, from within your _build_
directory Doxygen can be invoked using the __doc__ target:

    $> make doc

The documentation can then be found in _build_/doc/html/.

## License

The software is provided under the [BSD-3-Clause license](https://spdx.org/licenses/BSD-3-Clause.html).

## Feedback and Support

Arm welcomes any feedback on the DDS Security library.

To provide feedback or to request support please contact Arm by email at
support@arm.com. Arm licensees may also contact Arm via their partner
managers.

[1]: https://www.omg.org/spec/DDS/About-DDS/
[2]: https://developer.arm.com/technologies/trustzone
[3]: https://www.op-tee.org/
[4]: https://developer.arm.com/products/system-design/fixed-virtual-platforms/
[5]: https://community.arm.com/dev-platforms/
