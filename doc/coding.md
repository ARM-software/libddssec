The source code is divided in multiple subdirectories:

```
├── cmake
│   └── modules
├── CMakeLists.txt
├── doc                       // Contains the documentation of the project
│   └── CMakeLists.txt        // Sub CMake script for Doxygen
├── include
│   └── libddssec             // Public header files
├── src                       // Source files of the Client Application
├── tests                     // Source code of the tests and framework
│   ├── assets                // Contains list of assets used for the tests
│   ├── builtins
│   │   └── CMakeLists.txt    // Test Builtin calling
|   |                         //     cmake/modules/builtin_function.cmake
│   ├── CMakeLists.txt        // Sub CMake script for building the tests
├── tools                     // Various utility scripts (code checking,..)
└── trusted_application
    ├── builtins
    │   └── CMakeLists.txt    // TA Builtin calling
    |                         //     cmake/modules/builtin_function.cmake
    ├── CMakeLists.txt        // Cmake script building the TA using a makefile
    ├── include               // Public header files of the TA
    └── src                   // Source code of the TA
```

The top level `CMakeList.txt` will call the following sub directories:
- `doc/CMakeLists.txt`: Generation of the doxygen documentation
- `test/CMakeLists.txt`: Responsible for the tests
- `trusted_application/CMakelists.txt`: Building of the Trusted Application

Among calling those subscripts, the top level CMakeLists.txt looks for the
OP-TEE Client library and includes by loading the script
`cmake/modules/FindOPTEECLIENT.cmake`. It will also build the library.

# Adding a new TA source file.

- Create a new source file in `libddssec/trusted_application/src` with its
  associated header file.
- Potentially update the public include file located in
  `libddssec/trusted_application/include/dsec_ta.h` and the function
  `TA_InvokeCommandEntryPoint` from `libddssec/trusted_application/dsec_ta.c`
  with the new functions created with their associated opcode.
- Add the filename to the `sub.mk` in the same directory.

# Adding a new CA source file.

- Create a new source file in `libddssec/src` with its associated header file.
- Add this file in the variable `PROJECT_SOURCE` located in the CMake file
  `libddssec/CMakeLists.txt`.
- Include the following file `#include <dsec_ta.h>` to have access to the
  different `DSEC_TA_CMD_` opcodes used to call the TA specific functions.
- Use the common API created for the client application which is in the files
  `libddssec/src/dsec_ca.h` and `libddssec/src/dsec_ca.c`.

# Adding a new Test file.

- Copy paste the following template into a source file in the test area
  `libddssec/tests`:

```C
/*
 * DDS Security library
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dsec_errno.h>     /* For DSEC_E codes */
#include <dsec_filename.h>  /* File API that will be tested. */
#include <dsec_test.h>      /* For the test API and DSEC_TEST_ASSERT */
#include <dsec_test_ta.h>   /* Optional if the TA is not tested */

static void test_case_example(void)
{
    DSEC_TEST_ASSERT(true)
}

static const struct dsec_test_case_desc test_case_table[] = {
    DSEC_TEST_CASE(test_case_example),
};

const struct dsec_test_suite_desc test_suite = {
    .name = "Example Test Suite",
    .test_case_count = sizeof(test_case_table)/sizeof(test_case_table[0]),
    .test_case_table = test_case_table,
    .test_suite_setup = dsec_test_ta_setup, /* Only if the TA not needed. */
    .test_suite_teardown = dsec_test_ta_teardown, /* Optional, see above. */
};

```

Note: Depending on what is tested, the two functions `test_suite_setup` and
`test_suite_teardown` are not necessary. The specifics of these functions can
be found in the file `libddssec/tests/dsec_test_ta.c`.

- Once the test is created, it can be added to the CMake file
  `libddssec/tests/CMakeLists.txt`. Dependencies can also be added for a
  specific test. See the associated CMake function.

```CMake
dsec_add_test(
    NAME example_test_name
    SOURCE
        test_name_source.c
        ${CMAKE_SOURCE_DIR}/src/dsec_ca.c
        dsec_test_ta.c # If test_suite_setup or test_suite_teardown is set.
        other_source_dependencies.c
)
```

Note: There are multiple timers used for the tests:
- For the each test cases. The timeout is set to 6 minutes.
- For the test script in `tools/testbench.py`, the time to send, compile and run
  the test is bounded to 25 minutes. For each expected output after a command is
  started, the script will wait for 6 minutes before timeout.

# Adding new builtin to the tests or TA.

Builtin can be used in the tests or the TA. There are two different targets for
this:
- `builtins_ta` defined in `trusted_application/builtins/CMakeLists.txt` within
  the function `dsec_embed_asset_ta_files`. This is a dependency when building
  the TA in test and release mode.
- `builtins_test` defined in `tests/builtins/CMakeLists.txt` within the function
  `dsec_embed_asset_test_files`. This is a dependency when building the tests.

Those functions are calling the high level function `dsec_embed_asset_files`
located in `cmake/modules/builtin_function.cmake`. Which will get the specified
files and embed them into `[builddir]/builtins_list.h` where `[builddir]` must
be included when building the target that needs this dependency. The builtin
header file can then be included as: `#include <builtins/builtins_list.h>`.
