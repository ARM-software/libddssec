#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

"""
Check whether the files adhere to the prescribed coding style. Validation
is performed by checkpatch.pl.
Exit codes:
    0 Success
    1 Source code has style issues or the arguments to the tool were invalid
"""

import argparse
import os
import shutil
import sys
import subprocess
from utils import Walk

#
# Directories to ignore relative to where the tool is being invoked.
#
IGNORE = [
    '.git',
    'tools',
    'doc',
]

#
# Supported file types. Only used when --input-mode is set to "project".
#
FILE_TYPES = [
    '*.c',
    '*.h',
]

#
# Default ignored types. These are rules within checkpatch that conflict with
# the DDS Security library coding style and so they should never be enabled.
#
IGNORED_TYPES = [
    'LEADING_SPACE',  # Incompatible with spaces for indentation
    'CODE_INDENT',  # Incompatible with spaces for indentation
    'SUSPECT_CODE_INDENT',  # Incompatible with spaces for indentation
    'POINTER_LOCATION',  # Doesn't agree with our function declaration style
    'BLOCK_COMMENT_STYLE',  # Doesn't tolerate asterisks on each block line
    'AVOID_EXTERNS',  # We use the extern keyword
    'NEW_TYPEDEFS',  # We add new typedefs
    'VOLATILE',  # We use volatile
    'MACRO_WITH_FLOW_CONTROL',  # Some 'capture' macros use do/while loops
    'LINE_SPACING',  # We don't require a blank line after declarations
    'SPLIT_STRING',  # We allow strings to be split across lines
    'FILE_PATH_CHANGES',  # Specific to the kernel development process
    'SPDX_LICENSE_TAG',  # Not required as we have a dedicated tool for this
                         # and more
    'BRACES',  # Ignore braces warning for {} on single line 'if', 'else',
               # 'while',..
]

error_count = 0


def check_file(checkpatch_params, filename):
    global error_count

    cmd = '{} {}'.format(checkpatch_params, filename)

    try:
        subprocess.check_call(cmd, shell=True, stdin=0)
    except subprocess.CalledProcessError:
        error_count += 1


def main(argv=[], prog_name=''):
    print('DDS Security library checkpatch Wrapper')
    parser = argparse.ArgumentParser(
        prog=prog_name,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    input_mode_list = ['stdin', 'project']

    # Optional parameters
    parser.add_argument('-s', '--spacing', action='store_true',
                        help='Check for correct use of spaces',
                        required=False)

    parser.add_argument('-l', '--line-length', action='store_true',
                        dest='length',
                        help='Check for lines longer than 80 characters',
                        required=False)

    parser.add_argument('-i', '--initializers', action='store_true',
                        help='Check for redundant variable initialization',
                        required=False)

    parser.add_argument('-m', '--input-mode', choices=input_mode_list,
                        help='Input mode for the content to be checked',
                        required=False, default=input_mode_list[0])

    parser.add_argument('-p', '--path', action='store', dest='path',
                        help='Path to checkpatch.pl or the directory where '
                             'checkpatch.pl is located. When not set, '
                             'checkpatch.pl\'s directory must be in the PATH '
                             'environment variable.',
                        required=False)

    args = parser.parse_args(argv)

    checkpatch = 'checkpatch.pl'

    if args.path:
        if not os.path.exists(args.path):
            print("Error: path {} does not exist".format(args.path))
            sys.exit(1)

        if os.path.isfile(args.path):
            checkpatch = args.path

        else:
            checkpatch = os.path.join(args.path, checkpatch)

        if not os.path.exists(checkpatch):
            print("Error: checkpatch.pl not found using path {}"
                  .format(checkpatch))
            sys.exit(1)

    else:
        checkpatch = shutil.which(checkpatch)
        if checkpatch is None:
            print("Error: checkpatch.pl not found. Ensure checkpatch.pl's "
                  "path was added to the environment variable $PATH or use "
                  "the argument --path.")
            sys.exit(1)

    # Print the path to checkpatch.pl as confirmation
    print('checkpatch.pl path:{}\n'.format(checkpatch))

    # Enable optional tests
    if not args.spacing:
        IGNORED_TYPES.extend(['SPACING', 'MISSING_SPACE', 'BRACKET_SPACE'])

    if not args.length:
        IGNORED_TYPES.extend(['LONG_LINE', 'LONG_LINE_COMMENT',
                              'LONG_LINE_STRING'])
    if not args.initializers:
        IGNORED_TYPES.extend(['GLOBAL_INITIALISERS', 'INITIALISED_STATIC'])

    ignore_list = '--ignore ' + (','.join(map(str, IGNORED_TYPES)))

    checkpatch_params = '{} --show-types --no-tree --no-summary {}'.format(
        checkpatch,
        ignore_list,
    )

    if args.input_mode == 'project':
        print("Checking the coding style of the whole project...")
        checkpatch_params += ' --terse --file'
        walk = Walk(IGNORE, FILE_TYPES)

        for filename in walk.files():
            print("Checking " + filename)
            check_file(checkpatch_params, filename)

        if error_count > 0:
            print('{} files contained coding style errors.'.
                  format(error_count))

    elif args.input_mode == 'stdin':
        print("Checking content via standard input...")
        check_file(checkpatch_params, '-')

    else:
        print('FAILED: Invalid input mode')
        return 1

    if error_count > 0:
        print('FAILED: One or more files contained coding style errors.')
        return 1

    print('PASSED: No files contained coding style errors.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], sys.argv[0]))
