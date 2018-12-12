#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

"""
    Check for tabs in the source code.
"""
from utils import Walk
import argparse
import os
import shutil
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
    '*.c',
    '*.h',
    '*.in',
    '*.py',
    '.clang-format',
    '**CMakeLists.txt',
    '*.md',
]


class ErrorTab(Exception):
    pass


def convert(path):
    print("\tConverting all tabs in {} into spaces...".format(path))
    try:
        file, temp_file = tempfile.mkstemp(prefix='tabs_to_spaces_')
        print("Using {}".format(temp_file))
        subprocess.check_call('expand -t4 {} > {}'.format(path, temp_file),
                              shell=True)
        shutil.copyfile(temp_file, path)
    except Exception as e:
        print("Error: Failed to convert file {} with {}".format(path, e))
        sys.exit(1)
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def check_tabs(filename):
        print("processing {}".format(filename))
        with open(filename, encoding="utf-8") as file:
            for line, string in enumerate(file):
                if '\t' in string:
                    print('{}:{} has tab'.format(line, filename))
                    raise ErrorTab


def main(argv=[], prog_name=''):
    parser = argparse.ArgumentParser(prog=prog_name)
    parser.add_argument('-c', '--convert',
                        help='Convert tabs to 4 spaces.',
                        action='store_true',
                        default=False)
    args = parser.parse_args(argv)

    print('Checking the presence of tabs in the code...')
    if args.convert:
        print("Conversion mode is enabled.")

    error_tabs_count = 0

    cwd = os.getcwd()
    print("Executing from {}".format(cwd))

    #
    # Check files
    #
    walk = Walk(IGNORE, FILE_TYPES)
    for filename in walk.files():
        try:
            check_tabs(filename)
        except ErrorTab:
            error_tabs_count += 1
            if args.convert:
                convert(filename)

    if error_tabs_count == 0:
        print("No tabs found")
        return 0
    else:
        print('{} tab(s) found.'.format(error_tabs_count))
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], sys.argv[0]))
