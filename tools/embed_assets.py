#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

"""
    Convert a list of input files into a C-style header with metadata.
"""
import argparse
import sys


def write_array(input, output, variable_name):
    with open("{}".format(input), 'r') as f:
        output.write('static const uint8_t {}[] = {{\n'.format(variable_name))
        output.write('    ')

        columns = 12
        i = 0
        for byte in f.read():
            output.write('{},'.format(hex(ord(byte))))

            # Pretty-printing
            i += 1
            if i % columns == 0:
                output.write('\n    ')
            else:
                if ord(byte) < 0xF:
                    output.write('  ')
                else:
                    output.write(' ')

        output.write('\n};\n\n')


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--input-files',
                        required=True,
                        nargs='*')

    parser.add_argument('--output-file',
                        required=True,
                        nargs=1)

    parser.add_argument('--filenames',
                        required=True,
                        nargs='*')

    parser.add_argument('--variable-names',
                        required=True,
                        nargs='*')

    args = parser.parse_args(sys.argv[1:])

    with open("{}".format(args.output_file[0]), 'w') as output:
        output.write('/*\n'
                     ' * DDS Security library\n'
                     ' * Copyright (c) 2019, Arm Limited and Contributors. '
                     'All rights reserved.\n'
                     ' *\n'
                     ' * SPDX-License-Identifier: BSD-3-Clause\n'
                     ' */\n'
                     '\n'
                     '#ifndef DSEC_BUILTIN_OBJECTS_H\n'
                     '#define DSEC_BUILTIN_OBJECTS_H\n'
                     '#include <stddef.h>\n'
                     '#include <stdint.h>\n'
                     '\n'
                     'struct builtin_data {\n'
                     '    const char* const name;\n'
                     '    const uint8_t* const builtin;\n'
                     '    const size_t size;\n'
                     '};'
                     '\n'
                     '\n')

        i = 0
        for input in args.input_files:
            write_array(input, output, args.variable_names[i])
            i += 1

        output.write('static const struct builtin_data builtin_objects[] = {')
        i = 0
        for variable in args.variable_names:
            output.write('\n    {\n')

            output.write('        .name = "{}",\n'.format(args.filenames[i]))
            output.write('        .builtin = {},\n'.format(variable))
            output.write('        .size = sizeof({}),\n'.format(variable))

            output.write('    },')
            i += 1

        output.write('\n};'
                     '\n'
                     '\n'
                     '#endif /* DSEC_BUILTIN_OBJECTS_H */')

        # POSIX files must end on a newline
        output.write('\n')

    return 0


if __name__ == '__main__':
    sys.exit(main())
