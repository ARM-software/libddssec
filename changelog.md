# libddssec Change Log

Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.

# libddssec - version 0.1

This is the initial release of libddssec. The library is still under development
and currently only targets the Authentication plugin. Further DDS security
plugins (i.e. Cryptography) will be added in future releases.

This version of the project is considered experimental and should be used for
evaluation and development only.

## New features

- Builtin support: Embed security assets to the Trusted Application. Security
  assets can be Certificates, Certificate Authorities and Private Keys. These
  assets can only be added at build time.

- Authentication Plugin support: Added handles for Identification (Identity
  Handle), Handshake (Handshake Handle) and Shared Secret (Shared Secret
  Handle).

- Identity Handle: Loading of internal Certificate Authority, Certificate and
  Private Key. Loading of remote certificate buffer. Added associated
  operations: verification of a certificate, verification of a private key
  against a public key, signature generation of a given buffer using private
  key, verification of a signature using a public key.

- Handshake Handle: Generation of Diffie-Hellman public and private key
  (DH+MODP-2048-256), loading of a public Diffie-Hellman key buffer. Challenge
  generation for a handshake.

- Shared Secret Handle: Generation of shared secret using a valid Handshake
  Handle. The value of the shared secret key which is generated can be
  extracted.

- Doxygen and markdown files for documentation.

- Test framework for checking the library behavior.

- Tools for testing the library on different platforms using an FVP over telnet
  or a test machine over SSH. The tools can also be used for coding style checks
  and static analysis of the source code.

- CMake build system for building tests, source code, documentation, trusted
  applications.

## Known limitations

- No Certificate Revokation List (CRL) support.

- Missing rfc2253 as mbedTLS does not support it.

- No support for ECDH+prime256v1-CEUM.

## Tests

- This library has been tested on Armv8-A Base Platform FVP and Renesas RCar H3
  using the test suite through the `tools/validate.py` script.

- This library has been statically analysed using Coverity and CppCheck.

- This library code/script has been checked for coding style issues.

## Known issues

- While launching `build_ubuntu_image.sh`, if `alpine` is not configured the
  following error can occur:

```
standard_init_linux.go:207: exec user process caused "exec format error"
The command '/bin/sh -c bash -c "echo $SHLVL"' returned a non-zero code: 1
```

- While building the library, the following warning/error can occur if the
  Makefile is not using a shell that can parse the `{` for the `DSEC_TA_UUID`
  define.

```
<command-line>:0:0: warning: "DSEC_TA_UUID" redefined
<command-line>:0:0: note: this is the location of the previous definition
```
