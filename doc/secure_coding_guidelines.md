# Secure Coding Guidelines
---

The Secure Coding Guidelines is a set of coding practices with the aim to guard
against the accidental introduction of security vulnerabilities during the
development cycle of this project. Every patch must comply with the following:

- Any rules given should be followed as much as possible but exceptions can be
made if it makes development harder/less readable for particular cases.
Deviating a rule can be done if it properly documented.
- Follow the [Coding Guide](code_style.md) of the project.
- Declare global variables `const` unless they need to be modified.
- Declare function pointers as `const` if their content is not modified to show
other developers that they are used untouched.
- Inform a maintainer of all security bugs contained in a patch, and their
priority as they need to be added to the security track bar of the project.
- Keep the implementation as simple as needed. Ensure functions are short and do
only one task.
- Use a static code analysis tool. libddssec comes with a wrapper for Coverity:
  - Use `./tools/check_coverity.py --cross-compile --profile standard`
- The code complies with the MISRA C 2012 rules that are enforced by the
project. See [Deviated Rules](../tools/misra.config).
  - Use `./tools/check_coverity.py --cross-compile --profile misra`
- Check the versions of the third-party libraries and tools used by libddssec as
they could contain depreciated functions, security flaws. Keep in mind that:
  - The release tags of OP-TEE OS and OP-TEE Client should match.
  - mbedTLS is included by OPTEE-OS and might not be mainline.
  - The underlying layer of the Global Platform API used in OP-TEE OS is
  tomcrypt.

## libddssec specifics

When coding or reviewing a patch, take care of the following:

- Never leak data. This is an obvious one: secure assets should not be exposed
to normal world.
  - Do not print out assets in the Trusted Application (DMSG and EMSG).
- When a shared memref (`TEE_PARAM_TYPE_MEMREF_OUTPUT`) is updated in the
Trusted Application, the output size MUST be updated. The update of the buffer
can be done if the size of the given memory reference is big enough.
- When specifying a memref buffer as input (`TEEC_MEMREF_TEMP_INPUT`), make sure
the size of the buffer leads to an area in memory that can be shared. (If buffer
is `NULL`, size must be 0. If a buffer is of a fixed size, do not overflow).
- The Trusted Application NEVER trusts the Client Application inputs.
  - All inputs must be checked or handled with care:
    - Check the `TEE_Param` types as they should match with the given ones from
    the Client Application.
    - Check input size and if pointers are `NULL`.
- Do not put temporary results in the shared memory. This helps to avoid
leakage.
- Length of a message should be taken care to contain every byte of the message.
Do not use `strncmp` as it stops at '\0' (prefer `memcmp`), take care with
`strlen` as the size is given without `\0`,..
- Static arrays should be used where possible.
- Secure Storage of OPTEE-OS must never modify a stored file. The filesystem
created should be read only from the Client Application point of view.
  - Certificates, Private key, CRL should not be modified during run-time.
- Make sure to unload un-needed handle/assets or allocated structures. Some
functions in OPTEE-OS allocate space that must be released (`TEE_Allocate_*`,..)
- Make sure an `InvokeCommand` is non-blocking and not time consuming as it
could block the application running in the Non-Secure world.

## mbedTLS specifics

- mbedTLS must be used *ONLY* for certificate handling (X509 and ECC keys for
signature, verification). Otherwise, Global Platform API must be used.
- Make sure stored assets (certificates, private keys,..) contain a `\0` at the
end as mbedTLS expects this format when parsing.
