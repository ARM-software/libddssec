#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

import collections
import fnmatch
import os


class Walk:
    """
    Utility class to iterate through the source code files. This class will
    automatically ignore files and directories from a .gitignore. Further
    (explicit) files and directories can be ignored using the 'ignore'
    parameter in the constructor.

    Usage example:

        # Directories and files being ignored
        ignore = ['.git']

        # Files types to be scanned
        file_types = ['*.c', '*.h']

        walk = Walk(ignore, file_types)

        for filename in walk.files():
            do_something(filename)
    """

    __Pattern = collections.namedtuple('patterns', ['dirs_only', 'general'])

    def __is_ignored(self, filename, patterns):
        # Check if file is not in the ignore list
        for pattern in patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False

    def __is_valid_file(self, filename, patterns, file_types):
        for file_type in file_types:
            # Check if file is meant to be processed
            if fnmatch.fnmatch(filename, file_type):
                if self.__is_ignored(filename, patterns):
                    return False

                return True

        return False

    def __prepare_ignore_patterns(self, ignore):
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
                    raise NotImplementedError(
                        "Pattern {} not supported by this tool."
                        .format(line))

                patterns.append(line)

        # Add patterns from the explict ignore list
        patterns.extend(ignore)

        directory_patterns = []
        general_patterns = []

        # Split out patterns that affect directories only
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

        return self.__Pattern(dirs_only=directory_patterns,
                              general=general_patterns)

    def __init__(self, ignore, file_types):
        self.ignore_patterns = self.__prepare_ignore_patterns(ignore)
        self.file_types = file_types
        self.cwd = os.getcwd()

    def files(self):
        for root, dirs, files in os.walk(self.cwd, topdown=True):
            # Check if directory is ignored
            dirs[:] = [d for d in dirs if not self.__is_ignored(
                d,
                self.ignore_patterns.dirs_only)]

            for file in files:
                filename = os.path.relpath(os.path.join(root, file), self.cwd)
                if self.__is_valid_file(filename,
                                        self.ignore_patterns.general,
                                        self.file_types):
                    yield filename
