#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

import argparse
import check_EOF
import check_copyright
import check_tabs
import os
import platform
import subprocess
import sys
from testbench import TestBenchBase
from testbench import TestBenchFVP
from testbench import TestBenchSSH
from utils import build_directory


def banner(text):
    columns = 80
    title = ' {} '.format(text)
    print('\n\n{}'.format(title.center(columns, '*')))


def process_results(results):
    banner('Validation summary')

    total_success = 0
    total_skipped = 0
    for result in results:
        if result[1] is None:
            total_skipped += 1
            verbose_result = 'Skipped'
        elif result[1] == 0:
            total_success += 1
            verbose_result = 'Success'
        else:
            verbose_result = 'Failed'
        print('{}: {}'.format(result[0], verbose_result))

    total_attempted = len(results) - total_skipped
    assert total_success <= total_attempted

    if total_skipped == 1:
        print('1 test was skipped')
    else:
        print('{} tests were skipped'.format(total_skipped))
    print('{} / {} passed ({}% pass rate)\n'.format(
        total_success,
        total_attempted,
        int(total_success * 100 / total_attempted)))

    if total_success < total_attempted:
        return 1
    else:
        return 0


def run_unit_tests(args):

    results = []
    banner('Unit tests')

    if args.test_ssh:
        with build_directory():
            ssh_param = args.test_ssh.split(":")
            ssh_host = ssh_param[0]
            ssh_port = ssh_param[1] if len(ssh_param) > 1 else None

            try:
                with TestBenchSSH(ssh_host,
                                  args.prebuild_path,
                                  ssh_port=ssh_port) as t:
                    result = t.run()

            except TestBenchBase.Error as e:
                result = e.code

        results.append(('Unit tests on remote machine', result))

    if args.test_fvp:
        with build_directory():
            binary_path = os.path.expanduser(args.test_fvp[0])
            try:
                with TestBenchFVP(binary_path, args.prebuild_path) as t:
                    result = t.run()

            except TestBenchBase.Error as e:
                result = e.code

        results.append(('Unit tests on FVP', result))

    return results


def main():
    machine = platform.machine()
    results = []
    threads = len(os.sched_getaffinity(0))

    parser = argparse.ArgumentParser()
    target = parser.add_argument_group(
        'Unit tests',
        'Note: At least one unit test target must be selected')

    target.add_argument('--test-ssh',
                        help='Run unit tests on a target system via SSH. This \
                              argument requires the following parameters:\n\
                              <ip|hostname>[:port].\n\
                              The password and username for the target system \
                              are hardcoded in the script.',
                        required=False,
                        metavar="<ip|hostname>[:port]")

    target.add_argument('--test-fvp',
                        help='Run unit tests on a fast-model. This argument \
                              requires the following parameters:\n\
                              <path/to/system/binaries>',
                        required=False,
                        metavar="<path>",
                        nargs=1)

    target.add_argument('--prebuild-path', '-p',
                        help='Location of an existing build folder to use for \
                              the remote unit tests instead of building \
                              inside the remote machine. This argument \
                              requires the following parameters:\n\
                              <path/to/build/folder>',
                        required=False,
                        metavar="<path>",
                        default=None,
                        nargs=1)

    args = parser.parse_args(sys.argv[1:])
    if args.prebuild_path:
        args.prebuild_path =\
            os.path.abspath(os.path.expanduser(args.prebuild_path[0]))

    if not args.test_ssh and not args.test_fvp:
        print("No unit test target supplied\n", file=sys.stderr)
        parser.print_help()
        return 1

    banner('Style validation')

    result = check_copyright.main()
    results.append(('Check copyright', result))

    result = check_tabs.main()
    results.append(('Check tabs', result))

    result = check_EOF.main()
    results.append(('Check EOF', result))

    result = subprocess.call('pycodestyle --show-source tools/', shell=True)
    results.append(('Pycodestyle', result))

    with build_directory():
        subprocess.call('cmake ..', shell=True)
        result = subprocess.call('make doc', shell=True)
        results.append(('Check doc', result))

    banner('Builds')

    cmake_params = ''
    build_info = ''
    if machine == 'x86_64':
        print('Using cross-compilation')
        cmake_params += '-DCMAKE_TOOLCHAIN_FILE=../tools/toolchain.cmake'
        build_info += ' (cross-compiled)'

    with build_directory():
        subprocess.call('cmake {} ..'.format(cmake_params), shell=True)
        result = subprocess.call('make -j{}'.format(threads), shell=True)
        results.append(('Build libddssec{}'.format(build_info), result))
        library_build_result = result

    with build_directory():
        subprocess.call('cmake ..', shell=True)
        result = subprocess.call('make ta', shell=True)
        results.append(('Build trusted application', result))
        ta_build_result = result

    # Skip the unit tests if either build fails
    if library_build_result != 0 or ta_build_result != 0:
        print('Skipping unit tests - build failed')
        results.append(('Unit tests on remote machine', None))
        results.append(('Unit tests on FVP', None))
    else:
        result = run_unit_tests(args)
        for r in result:
            results.append(r)

    return process_results(results)


if __name__ == '__main__':
    sys.exit(main())
