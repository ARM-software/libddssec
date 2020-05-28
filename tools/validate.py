#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018-2020, Arm Limited and Contributors. All rights reserved.
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
import shutil
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


def run_unit_tests(args, prebuild_path):

    results = []
    banner('Unit tests')

    if args.target_ssh:
        with build_directory(persist=True, name='build-assets-ssh'):
            ssh_param = args.target_ssh.split(":")
            ssh_host = ssh_param[0]
            ssh_port = ssh_param[1] if len(ssh_param) > 1 else None

            try:
                with TestBenchSSH(ssh_host,
                                  prebuild_path,
                                  ssh_port=ssh_port) as t:
                    result = t.run()

            except TestBenchBase.Error as e:
                result = e.code

        results.append(('Unit tests on remote machine', result))

    if args.target_fvp:
        with build_directory(persist=True, name='build-assets-fvp'):
            binary_path = os.path.expanduser(args.target_fvp[0])
            try:
                with TestBenchFVP(binary_path, prebuild_path) as t:
                    result = t.run()

            except TestBenchBase.Error as e:
                result = e.code

        results.append(('Unit tests on FVP', result))

    return results


def main():
    machine = platform.machine()
    results = []
    threads = len(os.sched_getaffinity(0))
    prebuild_path = None

    parser = argparse.ArgumentParser()
    target = parser.add_argument_group(
        'Unit tests',
        'Note: At least one unit test target or --skip-tests must be selected')

    target.add_argument('--target-ssh',
                        help='Run unit tests on a target system via SSH. This \
                              argument requires the following parameters:\n\
                              <ip|hostname>[:port].\n\
                              The password and username for the target system \
                              are hardcoded in the script.',
                        required=False,
                        metavar="<ip|hostname>[:port]")

    target.add_argument('--target-fvp',
                        help='Run unit tests on a fast-model. This argument \
                              requires the following parameters:\n\
                              <path/to/system/binaries>',
                        required=False,
                        metavar="<path>",
                        nargs=1)

    target.add_argument('--skip-tests',
                        help='Only do the style validation and building of \
                              the tests. Tests are not excecuted.',
                        action='store_true')

    target.add_argument('--build-on-target', '-p',
                        help='Build tests natively on the target (e.g. \
                              FastModels). This option is much slower than \
                              using cross-compilation but has the benefit of \
                              testing a native build.',
                        required=False,
                        default=False,
                        action='store_true')

    args = parser.parse_args(sys.argv[1:])

    if not args.target_ssh and not args.target_fvp and not args.skip_tests:
        print("No unit test target or --skip-tests supplied\n",
              file=sys.stderr)
        parser.print_help()
        return 1

    banner('Style validation')

    result = check_copyright.main()
    results.append(('Check copyright', result))

    result = check_tabs.main()
    results.append(('Check tabs', result))

    result = check_EOF.main()
    results.append(('Check EOF', result))

    result = subprocess.call('pycodestyle --show-source tools/ '
                             '--exclude=arm_platform_build',
                             shell=True)
    results.append(('Pycodestyle', result))

    basedir = os.getcwd()
    with build_directory():
        subprocess.call('cmake -DBUILD_DOC=ON {}'.format(basedir), shell=True)
        result = subprocess.call('make doc', shell=True)
        results.append(('Check doc', result))

    banner('Builds')

    cmake_params = '-DBUILD_DOC=ON -DBUILD_TEST=ON '
    build_info = ''

    if machine == 'x86_64':
        print('Using cross-compilation')
        cmake_params += '-DCMAKE_TOOLCHAIN_FILE=../tools/toolchain.cmake'
        build_info += ' (cross-compiled)'

    persist_test_build = not args.build_on_target
    build_dir = 'build'

    with build_directory(persist=persist_test_build, name=build_dir) as \
            build_dir_name:
        subprocess.call('cmake {} {}'.format(cmake_params, basedir),
                        shell=True)

        result = subprocess.call('make -j{}'.format(threads), shell=True)
        results.append(('Build libddssec{}'.format(build_info), result))
        library_build_result = result

        result = subprocess.call('make test-ta'.format(threads), shell=True)
        results.append(('Build test-ta{}'.format(build_info), result))
        ta_build_result = result

        if persist_test_build:
            prebuild_path = build_dir_name

    with build_directory():
        subprocess.call('cmake {}'.format(basedir), shell=True)
        result = subprocess.call('make ta', shell=True)
        results.append(('Build trusted application', result))

    # Skip the unit tests if either build fails or if args.skip_tests is set
    if library_build_result != 0 or ta_build_result != 0 or args.skip_tests:
        print('Skipping unit tests')
        results.append(('Unit tests on remote machine', None))
        results.append(('Unit tests on FVP', None))
    else:
        result = run_unit_tests(args, prebuild_path)
        for r in result:
            results.append(r)

    if persist_test_build:
        shutil.rmtree(prebuild_path)

    return process_results(results)


if __name__ == '__main__':
    sys.exit(main())
