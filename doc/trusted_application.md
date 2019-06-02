The purpose of libddssec is to increase security by protecting critical assets
in TrustZone for a DDS library:
- Private Keys: Unique for a participant and stored in the Trusted Application
  (TA) before launching the DDS application.
- Session Keys: Generated after authentication and used for message exchange.
  Those keys are generated during run-time.

To prevent tampering of data, some non-critical assets are also stored in the
TrustZone storage. Those are public assets and part of them are exchanged during
the authentication process:
- Public certificate of the Certificate Authority (CA): used to authenticate the
  different remote participant certificates previously signed. This certificate
  is not sent through the DDS protocol and only stays locally in the node for
  verifying a participant certificate (local and remote). Tampering will cause
  the participant (local/remote) to be unauthenticated as the CA certificate
  won't authenticate the participant certificates.
- Public certificate of the local participant: used to authenticate a
  participant. If this certificate is tampered, the private key won't match, and
  the node signature won't be verified as the remote node won't get the same
  value of the hash contained in the signature received.


# 3-Way Handshake

## Basic background
When two participants (P1 and P2) want to communicate, the following three-way
handshake happens:

- Request: sent by P1 to P2 to initiate the key agreement protocol. It contains
  the public certificate of P1 (CertP1), the DH public key of P1 (DH1), and a
  challenge1 which is a nonce.

- Reply: sent by P2 to P1 in response to the Request message. It contains the
  public certificate of P2 (CertP2), the DH public key of P2 (DH2), challenge1
  and challenge2. The message is signed by P2 private key:

```
Sign(hash(CertP1) | challenge1 | DH1 | challenge2 | DH2 | hash(CertP2))
```

When P1 receives Reply, it checks the initially sent parameters (CertP1,
challenge1, DH1) to make sure they match the initial values. The signature is
verified using CertP2 containing the public key. CertP2 is also verified against
the Certificate Authority (CA). On success, the Shared Secret is generated on P1
side.

- Final: sent by P1 to P2 to confirm the receipt of Handshake-Reply. It contains
  both challenges and is signed by P1 private key.

```
Sign(hash(CertP1) | challenge1 | DH1 | challenge2 | DH2 | hash(CertP2))
```

When P2 receives Final, it checks all the sent parameters (CertP[1-2],
challenge[1-2], DH[1-2]) to make sure they match the values stored locally. The
signature is verified using CertP1 containing the public key. On success, the
Shared Secret is generated on P2 side.

# Trusted Application
The trusted application is divided in 3 main modules:
- Identity Handle (`ih`) composed of 3 submodules:

The `ih ca` (for Identity Handle Certificate Authority) is responsible for all
operations on a Certificate Authority within an Identity Handle. This module
handles loading/unloading a CA and verifying a certificate. It defines the
structure `ca_handle_t`.

The `ih cert` (for Identity Handle Certificate) is responsible for all
operations on Certificate within an Identity Handle. It handles
loading/unloading, getting a certificate outside the TA, getting information
about a certificate loaded, injecting a certificate to the TA, verifying a
private key, encrypting a buffer. This module defines the structure
`cert_handle_t`.

The `ih privkey` (for Identity Handle Private Key) is responsible for all
operations on Private Key within an Identity Handle. It handles
loading/unloading, signing a message buffer, verifying a signature. This module
defines the structure `privkey_handle_t`.

- Shared Secret Handle (`ssh`) composed of 2 submodules:

The `challenge` is responsible for operations related to local and remote
challenges generation and storage for a specific Shared Secret Handle.

The `ssh` is responsible for operations related to derivation of the shared key
secret and getting the values stored in the `shared_secret_handle_t`.

- Handshake Handle composed of 1 submodule and an ID to retrieve its associated
  `shared_secret_handle_t`:

The `hh dh` (Handshake Handle Diffie-Hellman) is responsible for operations
related to generating and storing Diffie-Hellman keys for a specific Handshake
Handle.

## Trusted Application call sequence.
The various modules have the following sequence to get a shared secret between
two nodes:
```
dsec_ta_ih_create
dsec_ta_ih_ca_load
dsec_ta_ih_cert_load
dsec_ta_ih_privkey_load
dsec_ta_ih_cert_get

* Exchange certificates *

dsec_ta_ih_cert_load_from_buffer // Set remote certificate

dsec_ta_hh_create
dsec_ta_hh_challenge_generate
dsec_ta_hh_challenge_get
* Exchange Challenges *
dsec_ta_hh_challenge_set_remote // Set remote challenge

dsec_ta_hh_dh_generate_keys
dsec_ta_hh_dh_get_public

* Exchange DH public keys *

dsec_ta_hh_dh_set_public // Set remote Diffie-Hellman Public key

dsec_ta_hh_ss_derive
```
Note: During the process, the signature of the message exchanged are verified to
make sure the communication is not compromised.
