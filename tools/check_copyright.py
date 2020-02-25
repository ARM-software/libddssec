#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

"""
Check if the project files include the correct license information.
"""

import datetime
import re
import subprocess
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
    '**Makefile',
    '*.cmake',
    '*Dockerfile*'
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


class ErrorNotAscending(Exception):
    pass


class ErrorYearNotCorrect(Exception):

    def __init__(self, right_year, wrong_year):
        self.right_year = right_year
        self.wrong_year = wrong_year


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

        # Send the porcelain status of the file to a pipe. Looks like:
        # M tools/check_copyright.py
        # for modified files, looks like:
        # A tools/new_file.py
        # for added files, and has no output for unmodified files
        proc = subprocess.Popen(['git', 'status', filename, '--porcelain'],
                                stdout=subprocess.PIPE)

        try:
            # The output will be empty when HEAD is clean, meaning indexing
            # it will raise an IndexError, handled below.
            status = proc.stdout.read().decode('utf-8')[1]
            if status != 'M' and status != 'A':
                raise IndexError

            year_last_touched = datetime.datetime.now().year

        except IndexError:  # There's no output because it hasn't been modified

            # Send the date that the file was last touched in this git tree to
            # a pipe. The output is in the format "YYYY-MM-DD" (including the
            # speech marks)
            proc = subprocess.Popen(['git', 'log', '-1', '--date=short',
                                     '--format="%cd"', filename],
                                    stdout=subprocess.PIPE)

            # Read the output and format to get the year
            # Index 0 is a speech mark
            try:
                year_last_touched = int(
                    proc.stdout.read().decode('utf-8')[1:5])
            except ValueError:
                year_last_touched = datetime.datetime.now().year

        years = match.group('years').split('-')
        if len(years) > 1:
            if years[0] >= years[1]:
                raise ErrorYear

        final_year = len(years) - 1
        last_year_listed = int(years[final_year])
        if last_year_listed != year_last_touched:
            raise ErrorYearNotCorrect(year_last_touched, last_year_listed)

        if years != sorted(years, key=int):
            raise ErrorNotAscending


def main():
    pattern = re.compile(LICENSE_PATTERN, re.MULTILINE)
    error_year_count = 0
    error_copyright_count = 0
    error_incorrect_year_count = 0
    error_not_ascending_count = 0

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

        except ErrorYearNotCorrect as e:
            print("{}: Incorrect copyright year range. Change {} to {}.".
                  format(filename, e.wrong_year, e.right_year))
            error_incorrect_year_count += 1

        except ErrorNotAscending:
            print("{}: Copyright years aren't ascending.".format(filename))
            error_not_ascending_count += 1

    if error_year_count != 0 or error_copyright_count != 0 or \
       error_incorrect_year_count != 0 or error_not_ascending_count != 0:
        print("\t{} files with invalid year(s) format."
              .format(error_year_count))
        print("\t{} files with invalid copyright."
              .format(error_copyright_count))
        print("\t{} files with incorrect year ranges."
              .format(error_incorrect_year_count))
        print("\t{} files with year ranges which aren't ascending."
              .format(error_not_ascending_count))

        return 1
    else:
        print("No errors found.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
