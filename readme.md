Readme
======

Copyright (c) 2018, Arm Limited. All rights reserved.

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

The following libraries are required:
- OpenSSL (1.0.2g or later): Used by the OpenSSL backend

Building the library
--------------------

Create a directory for the build output:

    $> mkdir build

Enter the build directory and run ```cmake```:

    $> cd build
    $> cmake ..

To build the library, use ```make```:

    $> make

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
