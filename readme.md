Readme
======

Copyright (c) 2018-2019, Arm Limited. All rights reserved.

Introduction
------------

In an autonomous future where machines are continually interacting with humans,
ensuring the operational correctness of these machines is going to be of
paramount importance. These machines are going to be commonplace, and a target
for misuse, malware and hacking on a daily basis.

By only allowing trusted nodes to interact with decision making parts of the
system, we can ensure that the system will always operate as the manufacturer
intended. Rogue items can be detected, and any data generated from these devices
can be discounted as untrusted.

The DDS Security library (__libddssec__) is an open source software library that
provides security services for implementations of the Data Distribution Service
(DDS) specification [1]. The main goal of the _libddssec_ is to offer a common
implementation of the security operations using different technologies. The
current implementation targets two backends:

* OP-TEE – Security operations are offloaded to run under a trusted environment
  (e.g. protected using Arm's TrustZone™).
* OpenSSL – Provides backwards compatibility on systems without a trusted
  environment support.

Prerequisites
-------------

To build __libddssec__, the following tools are required:

- CMake (3.5 or later)
- Gnu Make (4.1 or later)
- GCC (5.6 or later)

In addition, the following tools are recommended:

- Doxygen (1.8.11 or later): Required to build supporting documentation
- Dot (Graphviz 2.38 or later): Required to add diagrams in the documentation
- Python (3.5 or later): Required to run the Python based utilities under the
  tools/ directory
- checkpatch.pl (4.9 or later): Required by check_style.py.

The following libraries are required:
- OpenSSL (1.0.2g or later): Used by the OpenSSL backend

For the dependencies to build the trusted application, please consult the
[OPTEE-OS](https://github.com/OP-TEE/optee_os) documentation.

Building the library and trusted application
--------------------------------------------

Create a directory for the build output:

    $> mkdir build

Enter the build directory and run ```cmake```:

    $> cd build

    $> # Native compilation
    $> cmake ..

    $> # Cross compilation
    $> export TARGET_ARCH=<aarch64 | arm>
    $> export CROSS_COMPILE=<cross-compiler path and prefix>
    $> cmake -DCMAKE_TOOLCHAIN_FILE=../tools/toolchain.cmake ..

To build the library, use ```make```:

    $> make

To build the trusted application, use the target ```ta```. Ensure the
TA_DEV_KIT_DIR environment variable points to the OPTEE-OS build targeting your
platform. You may also set CROSS_COMPILE according to your development
environment. Example:

    $> export TA_DEV_KIT_DIR=<path to optee_os build>/<platform>/export-ta_xxx
    $> export CROSS_COMPILE=<cross-compiler path and prefix>
    $> make ta

To clean the trusted application build, use the target ```ta-clean```:

    $> make ta-clean

For more details on the OPTEE-OS environment variables, consult the
[OPTEE Examples](https://github.com/linaro-swg/optee_examples/blob/master/docs/TA_basics.md)
documentation.

Verification
------------

To build and run the unit tests:

    $> make build_and_test

The ```validation.py``` tool can be used during development to verify the code.
This tool will build and run the units as well check code style and
documentation. Execute the tool from the top level directory:

    ./tools/validation.py

Documentation
-------------

If Doxygen is available on the system containing the __libddssec__ then
comprehensive documentation can be generated. The complete set of documentation
is compiled into a bundle in HTML format and placed in the *_build_/doc*
directory.

After you create a build directory and run cmake, from within your _build_
directory Doxygen can be invoked using the __doc__ target:

    $> make doc

The documentation can then be found in _build_/doc/html/.

License
-------

The software is provided under the [BSD-3-Clause license](https://spdx.org/licenses/BSD-3-Clause.html).

References
----------

[1] https://www.omg.org/spec/DDS/About-DDS/


Feedback and Support
--------------------

Arm welcomes any feedback on the DDS Security library.

To provide feedback or to request support please contact Arm by email at
support@arm.com. Arm licensees may also contact Arm via their partner
managers.
