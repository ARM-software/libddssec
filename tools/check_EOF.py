#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

"""
    Check for missing newline before EOF in the source code.
"""
from utils import Walk
import argparse
import os
import subprocess
import sys
import tempfile

#
# Directories to exclude
#
IGNORE = [
    '.git',
    'build',
]

#
# Supported file types
#
FILE_TYPES = [
    '**CMakeLists.txt',
    '**Makefile',
    '*.c',
    '*.h',
    '*.in',
    '*.md'
    '*.mk'
    '*.py',
    '.clang-format',
]


class ErrorNoNewline(Exception):
    pass


def convert(path):
    print("\tAdding a newline to the end of {}...".format(path))
    try:
        subprocess.check_call('echo \'\' >> {}'.format(path),
                              shell=True)
    except Exception as e:
        print("Error: Failed to append newline {} with {}".format(path, e))
        sys.exit(1)


def check_EOF(filename):
        print("processing {}".format(filename))
        with open(filename, 'rb') as file:
            file.seek(-1, os.SEEK_END)
            byte = file.read()
            if byte != b'\n':
                print('{} is missing a newline at EOF'.format(filename))
                raise ErrorNoNewline


def main(argv=[], prog_name=''):
    parser = argparse.ArgumentParser(prog=prog_name)
    parser.add_argument('-c', '--convert',
                        help='Add missing newlines to EOF.',
                        action='store_true',
                        default=False)
    args = parser.parse_args(argv)

    print('Checking for missing newlines before EOF in the code...')
    if args.convert:
        print("Conversion mode is enabled.")

    error_missing_newline_count = 0

    cwd = os.getcwd()
    print("Executing from {}".format(cwd))

    #
    # Check files
    #
    walk = Walk(IGNORE, FILE_TYPES)
    for filename in walk.files():
        try:
            check_EOF(filename)
        except ErrorNoNewline:
            error_missing_newline_count += 1
            if args.convert:
                convert(filename)

    if error_missing_newline_count == 0:
        print("No missing newlines found")
        return 0
    else:
        print('{} missing newline(s) found.'
              .format(error_missing_newline_count))
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], sys.argv[0]))
