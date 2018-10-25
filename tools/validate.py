#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

import check_copyright
import check_EOF
import check_tabs
import contextlib
import os
import subprocess
import sys
import tempfile


def banner(text):
    columns = 80
    title = ' {} '.format(text)
    print('\n\n{}'.format(title.center(columns, '*')))


@contextlib.contextmanager
def build_directory():
    temp_dir = tempfile.TemporaryDirectory(prefix='build-', dir=os.getcwd())
    previous_path = os.getcwd()
    os.chdir(temp_dir.name)
    try:
        yield
    finally:
        os.chdir(previous_path)


def process_results(results):
    banner('Validation summary')

    total_success = 0
    for result in results:
        if result[1] == 0:
            total_success += 1
            verbose_result = 'Success'
        else:
            verbose_result = 'Failed'
        print('{}: {}'.format(result[0], verbose_result))

    assert total_success <= len(results)

    print('{} / {} passed ({}% pass rate)\n'.format(
        total_success,
        len(results),
        int(total_success * 100 / len(results))))

    if total_success < len(results):
        return 1
    else:
        return 0


def main():
    results = []
    threads = len(os.sched_getaffinity(0))

    banner('Style validation')

    result = check_copyright.main()
    results.append(('Check copyright', result))

    result = check_tabs.main()
    results.append(('Check tabs', result))

    result = check_EOF.main()
    results.append(('Check EOF', result))

    result = subprocess.call('pycodestyle tools/', shell=True)
    results.append(('Pycodestyle', result))

    with build_directory():
        subprocess.call('cmake ..', shell=True)
        result = subprocess.call('make doc', shell=True)
        results.append(('Check doc', result))

    banner('Builds')

    with build_directory():
        subprocess.call('cmake ..', shell=True)
        result = subprocess.call('make -j{}'.format(threads), shell=True)
        results.append(('Build libddssec', result))

    with build_directory():
        subprocess.call('cmake ..', shell=True)
        result = subprocess.call('make ta', shell=True)
        results.append(('Build trusted application', result))

    banner('Unit tests')

    with build_directory():
        subprocess.call('cmake ..', shell=True)
        result = subprocess.call('make build_and_test', shell=True)
        results.append(('Unit tests', result))

    return process_results(results)


if __name__ == '__main__':
    sys.exit(main())
