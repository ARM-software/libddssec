# Using libddssec                                              {#UsingLibddssec}

## Integrating libddssec into other projects

libddssec is designed to be used as an alternative to Normal World security with
libraries such as OpenSSL. Since libddssec-based DDS implementations should be
able to work with non-libddssec implementations or builds on other
architectures, integrating libddssec may be an option at build-time. This would
typically be achieved with CMake options, CFLAGS defines toggling between
sections of code, and/or choosing source files based on the architecture. Builds
using libddssec should link to the libddssec library.

It's also important to be able to toggle building and deployment of the Trusted
Application (TA).

libddssec's assets, APIs and steps for asset management should be familiar to
users of popular security libraries. The main difference is that assets are
passed around as handles to TEE assets rather than pointers to Normal World
data.

While libddssec is split into modules reflecting the security plugins from the
DDS standard, some modules will be dependent on others.

All public assets can be extracted out of the TEE and all remote assets can be
injected into the TEE. In contrast, private assets are generated and accessed
exclusively within the TEE. Since private assets must remain inside the TEE for
the entirety of their lifetime, extracting them to the Normal World to pass
their information to a Normal World security library is not an option. From
this, it follows that all of the possible operations upon an asset must be
implemented together. This limitation defines the minimum viability of a module
and the dependencies between modules.

To avoid security or safety issues from dynamically allocating memory for these
assets, any memory allocation that is necessary is done statically at startup,
implying a hard limit on the number of assets that can be stored at once in the
TEE. Additionally, accesses to the TA are single-threaded. While this can
potentially decrease performance for parallel applications, it reduces the
chance of safety or security issues from race-conditions.

libddssec v0.1 introduces the functionality to move the authentication plugin's
assets into the TEE both as a standalone module and as a base for which other
modules can build upon.

### Enabling libddssec-based builds

 - Add a toggle for inclusion of the libddssec headers.
 - Add a toggle for linking the libddssec library.
 - Add a toggle for building and/or deploying the libddssec TA.
 - Ensure that tee-supplicant is running on the machine the DDS implementation
   will be running on.
 - At the program's startup, initialize a dsec_instance in the DDS
   implementation (dsec_ca_instance_create).
 - At the program's end, tear-down the dsec_instance in the DDS implementation
   (dsec_ca_instance_close).

### Integrating the authentication module (PKI-DH)

While certificates are not considered a critical asset - they're transmitted
publicly - they are still stored in the TEE to prevent tampering with the
certificates which are loaded. Therefore, any code dealing with certificates
must be adapted to load or pass a handle to the data in the TEE rather than the
data loaded in memory itself. This can be achieved using functions such as @ref
dsec_ih_cert_load, which would load a handle to a given certificate. The full
range of operations available for Identity Handle certificates is:

 - @ref dsec_ih_create
 - @ref dsec_ih_delete
 - @ref dsec_ih_get_info
 - @ref dsec_ih_ca_load
 - @ref dsec_ih_ca_unload
 - @ref dsec_ih_ca_get_sn
 - @ref dsec_ih_ca_get_signature_algorithm
 - @ref dsec_ih_cert_load
 - @ref dsec_ih_cert_unload
 - @ref dsec_ih_cert_get
 - @ref dsec_ih_cert_get_sn
 - @ref dsec_ih_cert_get_signature_algorithm
 - @ref dsec_ih_cert_load_from_buffer
 - @ref dsec_ih_cert_verify
 - @ref dsec_ih_cert_get_sha256_sn
 - @ref dsec_ih_cert_get_raw_sn
 - @ref dsec_ih_privkey_load
 - @ref dsec_ih_privkey_unload
 - @ref dsec_ih_privkey_sign

For Diffie-Hellman public key exchange, both the public and private keys are
kept inside the TEE. Again, public keys are not critical data but keeping them
inside the TEE prevents tampering. Since the keys and the operations upon them
remain within the TEE, all functions managing keys in the DDS implementation
should be updated to use the libddssec key management operations.

Operations for Diffie-Hellman are:

 - @ref dsec_hh_create
 - @ref dsec_hh_delete
 - @ref dsec_hh_get_info
 - @ref dsec_hh_challenge_generate
 - @ref dsec_hh_challenge_get
 - @ref dsec_hh_challenge_unload
 - @ref dsec_hh_challenge_set
 - @ref dsec_hh_dh_generate
 - @ref dsec_hh_dh_get_public
 - @ref dsec_hh_dh_unload
 - @ref dsec_hh_dh_set_public

Once a handshake has been performed, the shared secret is also stored inside the
TEE. The operations for managing shared secrets are:

 - @ref dsec_ssh_derive
 - @ref dsec_ssh_get_data

### Deploying the Trusted Application (TA)

Instructions for building the TA can be found in the readme, requiring building
OP-TEE OS and exporting the TA development kit. Once built, the TA should be
copied to /lib/optee_armtz on the target system. Then, run tee-supplicant on the
target system so that the functions from the Normal World can access the
operations in the TA. Examples for this can be found in the test suite which
sets-up and tears-down the TA that is built for each test run.
