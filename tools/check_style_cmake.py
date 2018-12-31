#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

"""
Check if CMake files adhere to the prescribed coding style. Validation is
performed by cmakelint.

The following filter options are used:
    'linelength'            # Check if lines are <= 80 characters long
    'readability/logic'     # Check for expression repeated inside endif
    'readability/mixedcase' # Do not mix upper and lower case for commands
    'readability/wonkycase' # Do not use mixed case commands
    'whitespace/eol'        # Check if lines have no whitespace
    'whitespace/extra'      # Check for extra spaces between 'if' and its ()
    'whitespace/indent'     # Look for indentation mistakes
    'whitespace/mismatch'   # Check mismatching spaces inside () after command
    'whitespace/tabs'       # Look for tabs used instead of spaces

Exit codes:
    0 Success
    1 Source code has style issues or the tool could not be found
"""

import shutil
import sys
import subprocess
from utils import Walk

#
# Directories to ignore relative to where the tool is being invoked.
#
IGNORE = [
    '.git',
]

#
# Supported file types.
#
FILE_TYPES = [
    '*.cmake',
    '**CMakeLists.txt'
]

#
# Ignore some filters
#
IGNORED_FILTER_OPTIONS = [
]

error_count = 0


def check_file(filters, filename):
    global error_count

    cmd = 'cmakelint {} {}'.format(filters, filename)

    try:
        subprocess.check_call(cmd, shell=True, stdin=0)
    except subprocess.CalledProcessError:
        error_count += 1


def main(argv=[], prog_name=''):
    print('DDS Security library check CMake files Wrapper')

    if shutil.which("cmakelint") is None:
        print("Error: cmakelint not found. Ensure cmakelint is installed "
              "(pip install cmakelint)")
        sys.exit(1)

    # If there are no filtered options, enable all filters
    filter_options = '--filter=+'

    if len(IGNORED_FILTER_OPTIONS) > 0:
        filter_options = '--filter='
        filter_options += '-' + (',-'.join(map(str, IGNORED_FILTER_OPTIONS)))
        print("Ignoring: " + (' '.join(map(str, IGNORED_FILTER_OPTIONS))))

    print("Checking the coding style of all the CMake files in project...")
    walk = Walk(IGNORE, FILE_TYPES)

    for filename in walk.files():
        print("Checking " + filename)
        check_file(filter_options, filename)

    if error_count > 0:
        print('{} files contained coding style errors.'.
              format(error_count))

    if error_count > 0:
        print('FAILED: One or more files contained coding style errors.')
        return 1

    print('PASSED: No files contained coding style errors.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], sys.argv[0]))
