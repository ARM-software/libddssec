#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

"""
Check if the project files include the correct license information.
"""

import datetime
import re
import sys
from itertools import islice
from utils import Walk

#
# Directories to exclude
#
IGNORE = [
    '.git/',
]

#
# Supported file types
#
FILE_TYPES = [
    '*.c',
    '*.config',
    '*.h',
    '*.in',
    '*.py',
    '.clang-format',
    '**CMakeLists.txt',
    '**Makefile'
    '*.cmake',
]

#
# Supported comment styles (Python regex)
#
COMMENT_PATTERN = '^(( [*])|(;)|([#])|(//))'

#
# License pattern to match
#
LICENSE_PATTERN = \
    '{0} DDS Security library$\n'\
    '{0} Copyright [(]c[)] (?P<years>[0-9]{{4}}(-[0-9]{{4}})?), Arm Limited '\
    'and Contributors. All rights reserved.$\n'\
    '{0}$\n'\
    '{0} SPDX-License-Identifier: BSD-3-Clause$\n'\
    .format(COMMENT_PATTERN)

#
# The number of lines from the beginning of the file to search for the
# copyright header. This limit avoids the tool searching the whole file when
# the header always appears near the top.
#
# Note: The copyright notice does not usually start on the first line of the
# file. The value should be enough to include the all of the lines in the
# LICENSE_PATTERN, plus any extra lines that appears before the license. The
# performance of the tool may degrade if this value is increased significantly.
#
HEAD_LINE_COUNT = 10


class ErrorYear(Exception):
    pass


class ErrorCopyright(Exception):
    pass


class ErrorYearNotCurrent(Exception):
    pass


def check_copyright(pattern, filename):
    with open(filename, encoding="utf-8") as file:
        # Read just the first HEAD_LINE_COUNT lines of a file
        head_lines = islice(file, HEAD_LINE_COUNT)
        head = ''
        for line in head_lines:
            head += line

        match = pattern.search(head)
        if not match:
            raise ErrorCopyright

        years = match.group('years').split('-')
        if len(years) > 1:
            if years[0] > years[1]:
                raise ErrorYear

        now = datetime.datetime.now()
        final_year = len(years) - 1
        if int(years[final_year]) != now.year:
            raise ErrorYearNotCurrent


def main():
    pattern = re.compile(LICENSE_PATTERN, re.MULTILINE)
    error_year_count = 0
    error_copyright_count = 0
    error_incorrect_year_count = 0

    print("Checking the copyrights in the code...")

    walk = Walk(IGNORE, FILE_TYPES)
    for filename in walk.files():
        try:
            check_copyright(pattern, filename)
        except ErrorYear:
            print("{}: Invalid year format.".format(filename))
            error_year_count += 1

        except ErrorCopyright:
            print("{}: Invalid copyright header.".format(filename))
            error_copyright_count += 1

        except ErrorYearNotCurrent:
            print("{}: Outdated copyright year range.".
                  format(filename))
            error_incorrect_year_count += 1

    if error_year_count != 0 or error_copyright_count != 0 or \
       error_incorrect_year_count != 0:
        print("\t{} files with invalid year(s) format."
              .format(error_year_count))
        print("\t{} files with invalid copyright."
              .format(error_copyright_count))
        print("\t{} files with incorrect year ranges."
              .format(error_incorrect_year_count))

        return 1
    else:
        print("No errors found.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
