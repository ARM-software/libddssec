#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

"""
Check if a given file includes the correct license header.
This checker supports the following comment styles:
    * Used by .c, .h and .s/.S files
    # Used by Makefile (including .mk), .py (Python) and dxy (Doxygen) files
"""
import collections
import datetime
import fnmatch
import os
import re
import sys
from itertools import islice

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
    '*.h',
    '*.in',
    '*.py',
    '.clang-format',
    '**CMakeLists.txt',
]

#
# Supported comment styles (Python regex)
#
COMMENT_PATTERN = '^(( [*])|(;)|([#]))'

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


Pattern = collections.namedtuple('patterns', ['dirs_only', 'general'])


def is_ignored(filename, patterns):
    # Check if file is not in the ignore list
    for pattern in patterns:
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False


def is_valid_file(filename, patterns):
    for file_type in FILE_TYPES:
        # Check if file is meant to be processed
        if fnmatch.fnmatch(filename, file_type):
            if is_ignored(filename, patterns):
                return False

            return True

    return False


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


def prepare_ignore_patterns():
    patterns = []
    # Load ignore patterns from .gitignore
    not_supported = set('!\\')
    with open('.gitignore', 'r') as f:
        for l in f:
            line = l.strip()
            # Ignore empty lines
            if not line:
                continue
            # Ignore comments
            if line.startswith('#'):
                continue

            if any((c in not_supported) for c in line):
                print("Error: Pattern {} not supported by this tool."
                      .format(line))
                sys.exit(1)

            patterns.append(line)

    # Add patterns from the IGNORE list
    patterns.extend(IGNORE)

    directory_patterns = []
    general_patterns = []

    # Split out patterns that affect directory only
    for pattern in patterns:
        pattern = pattern.strip()

        if not pattern.endswith('/'):
            general_patterns.append(pattern)

        else:
            # Remove trailing slash
            pattern = pattern[:-1]

        # Note: patterns used to filter directory are not restricted to the
        # ones ending with '/'
        directory_patterns.append(pattern)

    return Pattern(dirs_only=directory_patterns, general=general_patterns)


def main():
    pattern = re.compile(LICENSE_PATTERN, re.MULTILINE)
    error_year_count = 0
    error_copyright_count = 0
    error_incorrect_year_count = 0

    print("Checking the copyrights in the code...")

    cwd = os.getcwd()
    print("Executing from {}".format(cwd))

    # Load exclude patterns
    patterns = prepare_ignore_patterns()

    for root, dirs, files in os.walk(cwd, topdown=True):
        # Check if directory is ignored
        dirs[:] = [d for d in dirs if not is_ignored(d, patterns.dirs_only)]

        for file in files:
            filename = os.path.relpath(os.path.join(root, file), cwd)
            if is_valid_file(filename, patterns.general):
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
