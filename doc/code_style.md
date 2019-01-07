Coding Style
============

To maintain consistency within the DDS Security library source code a series of
rules and guidelines have been created; these form the project's coding style.

Encoding
--------

The source code must use the UTF-8 encoding. Comments, documentation and strings
may use non-ASCII characters when required (e.g. Greek letters used for units).

Naming
------

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

Header Files
------------

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

Inclusions
----------

Header file inclusions should follow a consistent sequence, defined as:

- Headers from the DDS Security library
- Third party headers
- Standard library (stdbool, stdint, etc)

For each group, order the individual headers alphabetically.

Indentation and Scope
---------------------

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

Operator Precedence
-------------------

Do not rely on the implicit precedence and associativity of C operators. Use
parenthesis to make precedence and associativity explicit:

```C
if ((a == 'a') || (x == 'x'))
    do_something();
```

Parenthesis around a unary operator and its operand may be omitted:

```C
if (!a || &a)
    do_something();
```

Comments
--------

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

Macros and Constants
--------------------

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

Initialization
--------------

When local variables require being initialized to 0, please use their respective
type related initializer value:
- 0 (zero) for integers
- 0.0 for float/double
- \0 for chars
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

Structure initialization example:

```C
struct node node = {
    .name = "Node",
    .value = 42,
};
```

Doxygen Comments
----------------

The project APIs are documented using Doxygen comments.

It is mandatory to document every API exposed by the library.
By default, the provided Doxygen configuration omits undocumented elements from
the compiled documentation.

At a minimum:
- All functions and structures must have at least a "\brief" tag.
- All functions must document their parameters (if any) with the "\param" tag.
- All functions should use the "\return" or "\retval" tags to document their
return value. When the return is void, simply give "None" as the return value.

Alignment and indentation:
- Documentation must also obey the 80 columns limit.
- Multiple lines of documentation on an entry (e.g. details) must be indented
using the equivalent of two 4-space based tabs (see example below).

Function documentation example:

```C
/*!
 * \brief Enable a great feature.
 *
 * \details This function enables a great feature. It may be called multiple
 *      times without any side effects.
 *
 * \return None.
 */
void dsec_feature_enable(void);
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

Python based tools
------------------

Python based tools must follow the
[PEP8](https://www.python.org/dev/peps/pep-0008/) specification.
