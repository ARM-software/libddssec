# Coding Style
---

To maintain consistency within the DDS Security library source code a series of
rules and guidelines have been created; these form the project's coding style.

## Encoding

The source code must use the UTF-8 encoding. Comments, documentation and strings
may use non-ASCII characters when required (e.g. Greek letters used for units).

## C Coding Style
### Naming

Function, variable, file name and type names must:
- Be written in lower-case
- Have compound words separated by underline characters
- Have descriptive names, avoiding contractions where possible
  (e.g.count instead of cnt)

Do not use:
- Camel case syntax (e.g. moduleSecurityType)
- Hungarian notation, encoding types within names (e.g. int iSize)

Public functions, macros, types and defines must have the "dsec_" prefix
(upper case for macros and defines) used to identify the library API and avoid
name colision with other projects.

It is fine and encouraged to use a variable named "i" (index) for loops.

### Header Files

The contents of a header file should be wrapped in an 'include guard' to prevent
accidental multiple inclusion of a single header. The definition name should be
the upper-case file name followed by "_H". An example for dsec_auth.h follows:

```C
#ifndef DSEC_AUTH_H
#define DSEC_AUTH_H

(...)

#endif /* DSEC_AUTH_H */
```

The closing endif statement should be followed directly by a single-line comment
which replicates the full guard name. In long files this helps to clarify what
is being closed.

Space between definition inside the header file should be a single line only.

If a unit (header or C file) requires a header, it must include that header
instead of relying on an indirect inclusion from one of the headers it already
includes.

### Inclusions

Header file inclusions should follow a consistent sequence, defined as:

- Headers from the DDS Security library
- Third party headers
- Standard library (stdbool, stdint, etc)

For each group, order the individual headers alphabetically.

### Indentation and Scope

Indentation is made of spaces, 4 characters long with each line being at most 80
characters long.
Following K&R style, the open-brace goes on the same line as the statement:

```C
if (x == y) {
    (...)
}
```

The only exception is for functions, which push the opening brace to the
following line:

```C
void function_a(int x, int y)
{
  (...)
}
```

Similarly, the case and default keywords should be aligned with the switch
statement:

```C
switch (option) {
case 1:
    (...)
    break;
default:
    (...)
    break;
}
```

Conditional statements with single line of code must not use braces,
preferring indentation only. A statement that spans multiple lines must use
braces to improve readability:

```C
if (condition_a == true)
    function_call_a();

if (condition_b == true) {
    function_call_b(long_variable_name_x |
                    long_variable_name_y);
}
```

In a chain of if-else statements involving multi-line and single-line blocks,
it is acceptable to mix statements with and without braces:

```C
if (condition == [a]) {
    function_call_a(long_variable_name_x |
                    long_variable_name_y);
} else if (condition == [b])
    function_call_b();
```

Multi-line statements should align on the opening delimiter:

```C
long_variable_name = (long_variable_value << LONG_CONSTANT_POS) &
                      LONG_CONSTANT_MASK;
```

In case the code extends beyond 80 columns, the first line can wrap creating a
new indented block:

```C
                    long_variable_name =
                        (long_variable_value << LONG_CONSTANT_POS) &
                         LONG_CONSTANT_MASK;
```

When a stacked multi-line statement aligns with the next code level, leave a
blank line to highlight the separation:

```C
if (condition_a ||
    condition_b ||
    condition_c) {

    do_something();
}
```

Function definitions should follow the same approach:

```C
int foo(unsigned int param_a,
        unsigned param_b,
        unsigned param_c)
{
    ...
}
```

Preprocessor statements should be aligned with the code they are related to:

```C
#ifdef HAS_FOO
int foo(void)
{
    #ifdef HAS_BAR
    return bar();

    #else
    return -1;

    #endif
}
#endif
```

Where preprocessor statements are nested and they target the same code stream,
indentation is allowed but the hash symbol must be left aligned with the code
stream:

```C
#ifdef HAS_FOO
int foo(void)
{
    #ifdef HAS_BAR
    return bar();

    #else
    #   ifdef DEFAULT_ERROR
    return -1;

    #   else
    return 0

    #   endif
    #endif
}
#endif
```

__Note__ Such constructions like the example above should be avoided if
possible.

Types
-----

Import "stdint.h" (part of the C Standard Library) for exact-width integer types
(uint8_t, uint16_t, etc). These types can be used wherever the width of an
integer needs to be specified explicitly.

Import "stdbool.h" (also part of the C Standard Library) whenever a "boolean"
type is needed.

Avoid defining custom types with the "typedef" keyword where possible.
Structures (struct) and enumerators (enum) should be declared and used with
their respective keyword identifiers. If custom types are used then they must
have the suffix "_t" appended to their type name where it is defined. This makes
it easier to recognize types that have been defined using "typedef" when they
appear in the code.

When using sizeof() pass the variable name as the parameter to be evaluated, and
not its type. This prevents issues arising if the type of the variable changes
but the sizeof() parameter is not updated.

```C
size_t size;
unsigned int counter;

/* Preferred over sizeof(int) */
size = sizeof(counter);
```

When local variables require being initialized to 0, please use their respective
type related initializer value:
- 0 (zero) for integers
- 0.0 for float/double
- '\0' for chars
- NULL for pointers
- false for booleans (stdbool.h)

Array and structure initialization should use designated initializers. These
allow elements to be initialized using array indexes or structure field names
and without a fixed ordering.

Array initialization example:

```C
uint32_t key[3] = {
    [0] = 123,
    [1] = 456,
};
```

When evaluating the boolean result of a pointer content, use explicit comparison
against NULL:

```C
    if (ptr != NULL)
        do_something();
```

Structure initialization example:

```C
struct node node = {
    .name = "Node",
    .value = 42,
};
```

### Operator Precedence

Do not rely on the implicit precedence and associativity of C operators. Use
parenthesis to make precedence and associativity explicit:

```C
if ((a == 'a') || (x == 'x'))
    do_something();
```

Parenthesis around a unary operator and its operand may be omitted:

```C
if (!a || !b)
    do_something();
```

### Comments

To ensure a consistent look, the preferred style for single-line comments is to
use the C89 style of paired forward-slashes and asterisks:

```C
/* A short, single-line comment. */
```

For multi-line comments the same applies, adding an asterisk on each new line:

```C
/*
 * This is a multi-line comment
 * where each line starts with
 * an asterisk.
 */
```

### Macros and Constants

All names of macros and constants must be written in upper-case to differentiate
them from functions and variables.

Logical groupings of constants should be defined as enumerations, with a common
prefix, so that they can be used as parameter types. To find out the number of
items in an "enum", make the last entry to be \<prefix\>_COUNT.

```C
enum command_id {
    COMMAND_ID_VERSION,
    COMMAND_ID_FOO,
    COMMAND_ID_BAR,
    /* Do not add entries after this line */
    COMMAND_ID_COUNT
};

void process_cmd(enum command_id id)
{
    (...)
}
```

Prefer inline functions instead of macros.

### Doxygen Comments

The project APIs are documented using Doxygen comments.

It is mandatory to document every API exposed by the library and each interface
exposed by the trusted application.
By default, the provided Doxygen configuration omits undocumented elements from
the compiled documentation.

Every header file containing public API must include:
- A "\file" tag which will instruct Doxygen to show the header file name
  allowing the user to know which header file needs to be included.
- APIs must be enclosed by a Group definition used organize them in sections.


File documentation example (dsec_foo.h):

```C
/*
 * DDS Security library
 * Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * \file
 * \brief \copybrief GroupFoo
 */

#ifndef DSEC_FOO_H
#define DSEC_FOO_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \defgroup GroupFoo Foo
 *
 * \brief Foo group description.
 * \{
 */

[... API ...]

/*!
 * \}
 */

#ifdef __cplusplus
}
#endif

#endif /* DSEC_FOO_H */
```

At a minimum:
- All functions, structures and defines must have a "\brief" entry.
- All functions must document their parameters (if any) with the "\param" tag.
- Pointers to storage used to return data from a function should be decorated
  with the "[out]" tag. \param [out] ptr Pointer to buffer
- All functions should document their return value:
  - Use "\retval" tag to specify individual values
  - Use the "\return" tag to describe the possible values
  - When the return is void, simply use "\return None."

Alignment and indentation:
- Documentation must also obey the 80 columns limit.
- Multiple lines of documentation on an entry (e.g. details) must be indented
  using the equivalent of two 4-space based tabs (see example below).

References:
- When making references to other symbols (e.g. structs or functions), you must
  use \ref. Apart from creating a link on the generated documentation, this will
  also ensure broken links (e.g. when updating API names) are caught during the
  document generation.
- \return and \retval, do not allow using \ref. In this case, you must prepend
  :: (double colon) to the symbol being referred to.

Function documentation examples:

```C
/*!
 * \brief Enable a great feature.
 *
 * \details This function enables a great feature. It may be called multiple
 *      times without any side effects.
 *
 * \return None.
 */
void dsec_foo_feature_enable(void);

/*!
 * \brief Do something.
 *
 * \details This function does something and returns it on buffer.
 *
 * \param [out] buffer Pointer to storage where random data will be written.
 * \param size Buffer size in bytes.
 *
 * \retval ::DSEC_SUCCESS Success.
 * \retval ::DSEC_E_PARAM buffer pointer is invalid (NULL).
 */
int dsec_foo_do(void *buffer, size_t size);
```

Structure documentation example:

```C
/*!
 * \brief A node descriptor
 */
struct node {
    /*! Node's name */
    const char *name;

    /*! A value the node carries */
    unsigned int value;
};
```

## Python based tools

Python based tools must follow the
[PEP8](https://www.python.org/dev/peps/pep-0008/) specification.

## Git Commit message

When contributing to libddssec, Git commit messages must follow these rules:

- Try to keep the subject line under 50 characters
- Try to keep the message body under 72 characters
- Capitalize the subject line and do not end it with a period
- Summarize 'what' is the commit adding/changing and describe 'why' it is
  required
- Commits must have a 'Signed-off-by:' entry

## CMake Style

CMake files (CMakeLists.txt and .cmake) must follow the following rules.
Some of the above rules are enforced by the use of ``cmakelint`` tool.

- CMake version should be set to 3.5: ``cmake_minimum_required(VERSION 3.5)``
- No use of tabs
- Indentation size is 4 spaces
- Maximum 80 columns per line
  - To avoid unwanted indentation for strings, use a temporary variable as
follows:
```CMake
string(CONCAT WARNING_MSG
    "The variable FOUND_LIBRARIES does not seem to be properly defined. "
    "Its value is set to: "
    "${FOUND_LIBRARIES} and seems invalid..."
)
message(WARNING ${WARNING_MSG})
```
- Long lines must be broken as follows:
  - The closing parenthesis should be indented with the function name
  - Arguments must starts with 1 indentation:
```CMake
function_name(
    ${ARGUMENT_NAME}
    COMMAND
        ${EXECUTABLE}
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}
)
```
- Long control statements should be splited as follows:
```CMake
if(LONG_VARIABLE_CONDITION1 OR
    LONG_VARIABLE_CONDITION2 AND
    LONG_VARIABLE_CONDITION3)

    statement1
```
- CMake and custom functions (e.g. ``set()``, ``find_package()``), control
statements (e.g. ``if()``, ``else()``) must be written in lower-case
- Custom functions and variables must have compound words separated by underline
characters
- All variables declared must be uppercase
- Mixing upper and lower cases is forbidden
- Use empty commands for ``end*()`` and ``else()``
- Do not add spaces before and after parenthesis: ``if ( FOUND )`` is
forbidden and must be written ``if(FOUND)``
- When assigning paths to variables, do not include a slash at the end
