#!/usr/bin/env python3
#
# DDS Security library
# Copyright (c) 2018-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

import os
import pexpect
import re
import subprocess
import sys
import shutil


class TestBenchBase:

    password = '1234'
    username = 'root'

    prompt = '{}@'.format(username)

    # OPTEE client development files and library
    optee_client_dir = '$HOME/optee_client'

    # OPTEE devkit used to build trusted applications. The devkit is generated
    # during the OPTEE OS build and must match the target platform.
    ta_dev_kit_dir = '$HOME/ta_dev_kit'

    # Directory containing libddssec assets (source code and prebuild files)
    assets_directory = '/dev/shm/libddssec'

    # Directory where the tests are built and run from
    test_directory = '/dev/shm/test'

    # Directories required by OPTEE during run-time (not used by this tool)
    required_dirs = ['/dev/shm/lib/optee_armtz',  # Used to deploy TAs
                     '/dev/shm/data']  # Used for secure storage

    # Directory containing assets to be sent back to the host
    output_assets_directory = '/dev/shm/output_assets'

    # Size of the buffer that is kept in memory to find the expected output
    maxread_buffer_size = 100000000
    # Size of the buffer that will be searched for input
    searchwindow_size = 100

    def __init__(self, prebuild_path=None):
        self.prebuild_path = prebuild_path
        self.assets_tar = AssetsTar(self.prebuild_path)
        self.test_archive = self.assets_tar.name
        self.terminal = None
        self.exit_code = None

    def _do(self, command, expect=[], unexpect=[]):
        self.terminal.sendline(command)

        # Slow or complicated commands might show the prompt before they're
        # completed. Use this to specify extra strings to expect before the
        # prompt.
        for x in expect:
            while True:
                # Wait for an expected output
                match_list = [x] + unexpect
                index = self.terminal.expect(match_list)
                if index == 0:
                    # The return index value is one of the given index of the
                    # specified list while calling the expect function
                    break
                elif index != 0:
                    # trigger error and break
                    raise self.Error(output=match_list[index])

        self.terminal.expect_exact(self.prompt)
        self._get_exit_code(command)

    def _get_exit_code(self, command, return_values=[0]):
        old_logfile = self.terminal.logfile
        self.terminal.logfile = None

        # \r needed so that it will match all of a multi-digit exit code.
        # N.B. Telnet uses Windows-style line-endings
        self.terminal.sendline('echo $?')
        self.terminal.expect('\n+[0-9]{1,3}\r*\n')

        # So much for duck-typing
        self.exit_code = int(self.terminal.after.decode('utf8'))

        self.terminal.logfile = old_logfile

        if self.exit_code not in return_values:
            raise self.Error(self.exit_code, command=command)

    def run(self):
        do = self._do

        print('Connecting to remote...')

        try:
            index = self.terminal.expect(['login:', '[pP]assword:'])
            if index == 0:
                # Over keyless ssh, the username is supplied with the command
                # so it only asks for the password.
                self.terminal.sendline(self.username)
                self.terminal.expect(['[pP]assword:'])

            self.terminal.sendline(self.password)
            print('Logged in')

            do('mkdir -p {}'.format(self.assets_directory))
            do('mkdir -p {}'.format(self.output_assets_directory))
            do('mkdir -p {}/build'.format(self.test_directory))

            for directory in self.required_dirs:
                do('mkdir -p {}'.format(directory))

            self._setup_assets()

            do('cd {}'.format(self.assets_directory))
            do('tar xf {}/{} -C {}'.format(
                self.assets_directory, self.test_archive, self.test_directory))

            do('cd {}/build'.format(self.test_directory))

            if self.prebuild_path:
                do('ctest -VV',
                   expect=['100% tests passed, 0 tests failed'],
                   unexpect=['Errors while running CTest'])

            else:
                do('export OPTEECLIENT_DIR={}'.format(self.optee_client_dir))
                do('cmake -DBUILD_TEST=ON ..',
                    expect=['Build files have been written to'],
                    unexpect=['Configuring incomplete, errors occurred!',
                              'CMake Error'])

                print("Building...")
                do('export TA_DEV_KIT_DIR={}'.format(self.ta_dev_kit_dir))
                do('make test-ta', expect=['Building trusted application',
                                           'Built target test-ta'])
                do('make build_and_test',
                   expect=['Built target build_and_test'],
                   unexpect=['recipe for target \'build_and_test\' failed'])

        except (pexpect.exceptions.TIMEOUT, pexpect.exceptions.EOF):
            # If there was an error within the connection (TIMEOUT or EOF) it
            # might be because the ssh session or telnet was not opened
            # properly or hanged.
            print("Exiting as something went wrong with remote: pexpect "
                  "received an unexpected TIMEOUT or EOF.")
            self.exit_code = 1
            self.terminal.close()

        # Stop printing into logfile
        self.terminal.logfile = None
        return self.exit_code

    def _copy_output_assets(self):
        # Archive output assets into a single tar file
        output_assets_tar = '/dev/shm/output_assets.tar'
        self._do('tar cf {} -C {} {}'.format(
                 output_assets_tar,
                 os.path.dirname(self.output_assets_directory),
                 os.path.basename(self.output_assets_directory)))

        self._host_copy(output_assets_tar)

    def _cleanup(self):
        self.terminal.logfile = None
        self._do('cd /')
        self._do('rm -rf {}'.format(self.test_directory))
        self._do('rm -rf {}'.format(self.output_assets_directory))

    class Error(Exception):
        def __init__(self, code=1, command=None, output=None):
            print('Error:')
            if command:
                print('Command:\n{}'.format(command))
                print('Gave an unexpected exit code {}.'.format(code))

            if output:
                print('Unexpected output:\n{}'.format(output))
            self.code = code


class TestBenchFVP(TestBenchBase):

    device = '/dev/mmcblk0'

    def __init__(self, binary_path, prebuild_path=None):
        super().__init__(prebuild_path)
        self.binary_path = binary_path

        # Base addresses
        address_dtb = '0x82000000'
        address_kernel = '0x80080000'
        address_ramdisk = '0x84000000'

        # Binary names
        bl1 = 'bl1.bin'
        dtb = 'fvp-base-aemv8a-aemv8a.dtb'
        fip = 'fip.bin'
        kernel = 'Image'
        ramdisk = 'ramdisk.img'
        self.disk = 'ubuntu.img'

        # Create the libddssec assets to be used as an external drive
        self.assets_img = AssetsImage(self.assets_tar)
        self.test_archive = self.assets_tar.name

        args = ''.join(
            ['FVP_Base_RevC-2xAEMv8A',
                ' -C bp.hostbridge.userNetworking=true',
                ' -C bp.vis.disable_visualisation=true',
                ' -C bp.terminal_0.start_telnet=false',
                ' -C bp.terminal_1.start_telnet=false',
                ' -C bp.smsc_91c111.enabled=1',
                ' -C pctl.startup=0.0.0.0',
                ' -C cluster0.NUM_CORES=0x1',
                ' -C cluster1.NUM_CORES=0x1',
                ' -C cache_state_modelled=0',
                ' -C bp.pl011_uart0.untimed_fifos=1',
                ' -C bp.ve_sysregs.mmbSiteDefault=0',
                ' -C bp.ve_sysregs.exit_on_shutdown=1',
                ' -C bp.secureflashloader.fname={}/{}'.format(
                    self.binary_path, bl1),
                ' -C bp.flashloader0.fname={}/{}'.format(
                    self.binary_path, fip),
                ' -C bp.virtioblockdevice.image_path={}/{}'.format(
                    self.binary_path, self.disk),
                ' -C bp.mmc.p_mmc_file={}'.format(self.assets_img.path),
                ' --data cluster0.cpu0={}/{}@{}'.format(
                    self.binary_path, kernel, address_kernel),
                ' --data cluster0.cpu0={}/{}@{}'.format(
                    self.binary_path, dtb, address_dtb),
                ' --data cluster0.cpu0={}/{}@{}'.format(
                    self.binary_path, ramdisk, address_ramdisk)])

        print("Launching FVP with {}".format(args))
        self.child = pexpect.spawn(args, timeout=60)

        # Find the telnet port for the fast-model using RegEx on its output
        match =\
            'terminal_0: Listening for serial connection on port [0-9]{4}\r'
        sub_match = '[0-9]{4}'
        self.child.expect(match)
        self.telnet_port =\
            re.search(sub_match, self.child.after.decode('utf-8')).group(0)

        print('Using port {}'.format(self.telnet_port))

    def __enter__(self):
        self.terminal = pexpect.spawn(
            'telnet localhost {}'.format(self.telnet_port),
            timeout=3200,  # Set default timeout for expect()
            logfile=sys.stdout.buffer,
            maxread=self.maxread_buffer_size,
            searchwindowsize=self.searchwindow_size,
            echo=False)
        return self

    def _setup_assets(self):
        self._do('mount -rw {} {}'.format(self.device, self.assets_directory))

    # Uses the SD card as a method of getting files out of the model. Files are
    # copied to the SD card inside the model, then the image of the SD card is
    # copied to the destination in the host. After this, the source file(s) are
    # dumped outside of the SD card image using debugfs to read from the SD
    # card image without needing superuser.
    def _host_copy(self, tar_filename):
        # Move the file to the mount location of the SD card image
        self._do('mv {} {}'.format(tar_filename, self.assets_directory))
        self._do('sync')
        self._do('umount {}'.format(self.assets_directory))

        try:
            subprocess.check_call('debugfs -R \"rdump {} .\" {}'.format(
                os.path.basename(tar_filename), self.assets_img.name),
                shell=True)
            subprocess.check_call('tar xf {}'.format(
                os.path.basename(tar_filename)), shell=True)
        except subprocess.CalledProcessError as e:
            raise self.Error(code=e.returncode, command=e.cmd)

    def __exit__(self, *args):
        # If the remote cannot be accessed, the following commands cannot be
        # executed.
        if self.terminal.isalive():
            self._copy_output_assets()
            self._cleanup()
            self.terminal.sendline('shutdown -P now')

        self.child.terminate(force=True)
        # Stall until the filesystem is unused and can be removed
        self.child.wait()


class TestBenchSSH(TestBenchBase):

    def __init__(self, ssh_ip, prebuild_path=None, ssh_port=None):
        super().__init__(prebuild_path)
        self.ssh_ip = ssh_ip
        self.ssh_port = ssh_port
        self.ssh_port_string = ''

    def _setup_assets(self):

        if self.ssh_port:
            self.ssh_port_string = '-P {}'.format(self.ssh_port)

        scp_command = \
            'scp {} {} {}@{}:{}'.format(self.ssh_port_string,
                                        self.assets_tar.path,
                                        self.username,
                                        self.ssh_ip,
                                        self.assets_directory)

        print('Copying assets to remote...')
        terminal = pexpect.spawn(scp_command, timeout=60)
        with terminal:
            terminal.expect(['[pP]assword:'])
            terminal.sendline(self.password)
            terminal.expect(pexpect.EOF)

    # Copy to the destination on the host by placing the source in a tarball
    # and using a secure copy (scp) pull from the host using the known IP
    # address of the remote machine.
    def _host_copy(self, tar_filename):
        scp_command = \
            'scp {} {}@{}:{} .'.format(self.ssh_port_string,
                                       self.username,
                                       self.ssh_ip,
                                       tar_filename)

        terminal = pexpect.spawn(scp_command, timeout=60)
        with terminal:
            terminal.expect(' password:')
            terminal.sendline(self.password)
            terminal.expect(pexpect.EOF)

        try:
            subprocess.check_call('tar xf {}'.format(
                os.path.basename(tar_filename)), shell=True)
        except subprocess.CalledProcessError as e:
            raise self.Error(code=e.returncode, command=e.cmd)

    def __enter__(self):
        ssh_command = 'ssh {}@{}'.format(self.username, self.ssh_ip)
        if self.ssh_port:
            ssh_command += ' -p {}'.format(self.ssh_port)

        self.terminal = pexpect.spawn(
            ssh_command,
            timeout=600,  # Set default timemout for expect()
            logfile=sys.stdout.buffer,
            maxread=self.maxread_buffer_size,
            searchwindowsize=self.searchwindow_size,
            ignore_sighup=True,
            echo=True)

        return self

    def __exit__(self, *args):
        # If the remote cannot be accessed, the following commands cannot be
        # executed.
        if self.terminal.isalive():
            self._copy_output_assets()
            self._cleanup()
            self._do('rm -rf {}'.format(self.assets_directory))
            self.terminal.sendline('exit')


class AssetsTar():

    def __init__(self, prebuild_path=None):
        self.name = 'test.tar'
        self.path = os.path.abspath(self.name)

        proc = subprocess.Popen(
                    ['git', 'rev-parse', '--show-toplevel'],
                    stdout=subprocess.PIPE)

        project_base_dir = proc.stdout.read().strip().decode('utf-8')
        working_dir = os.getcwd()

        prebuild_tar = os.path.abspath('build.tar')

        os.chdir(project_base_dir)

        # List all the source files that should be tar-ed for the target:
        #   - files that are untracked and not in .gitignore
        #   - files that are tracked in the project
        # All files that were deleted and previously tracked are discarded.
        list_cmd = '''(if test -z "`git ls-files --deleted`" ; then
                          git ls-files --others --exclude-standard && \
                          git ls-files
                       else
                          (git ls-files --others --exclude-standard && \
                           git ls-files) | \
                          grep --invert-match "`git ls-files --deleted`"
                       fi)'''

        archive_cmd = '''{} | tar -cf {} -T -'''.format(list_cmd, self.path)

        subprocess.check_call(archive_cmd, shell=True)

        # When using pre-build mode, include also the 'build' directory into
        # the assets being sent to the target.
        if prebuild_path:
            # Create a tar-file (build.tar) of the 'build' directory
            subprocess.check_call('tar cf {} build'.format(prebuild_tar),
                                  shell=True)
            # Concatenate build.tar into test.tar
            subprocess.check_call('tar --concatenate --file={} {}'.format(
                        self.path, prebuild_tar), shell=True)

        os.chdir(working_dir)


class AssetsImage():

    name = 'libddssec.img'

    def __init__(self, assets_tar):
        self.path = os.path.abspath(self.name)

        print('Creating libddssec image')

        try:
            # Disk geometry
            disk_size_alignment = 512 * 1024
            block_size = 1024
            assert (disk_size_alignment % block_size == 0), \
                "Block size is not a multiple of {}".format(
                    disk_size_alignment)

            # Calculate the minimum disk size as being 16MiB + the size of
            # the input assets.
            # The minimum size may need to be tweaked in the future if the
            # output assets increase beyond this capacity.
            size_min = (16 * 1024 * 1024) + os.path.getsize(assets_tar.path)

            # Align disk size
            disk_size = int((size_min + disk_size_alignment - 1) /
                            disk_size_alignment) * disk_size_alignment

            block_count = int(disk_size / block_size)

            print("Disk details:\n"
                  "\tMinimum size required: {} bytes\n"
                  "\tBlock size: {} bytes\n"
                  "\tTotal blocks: {}\n"
                  "\tDisk size alignment: {} bytes\n"
                  "\tFinal disk size: {} bytes".format(size_min, block_size,
                                                       block_count,
                                                       disk_size_alignment,
                                                       disk_size))

            subprocess.check_call('dd of={} bs={} count={} if=/dev/zero'
                                  .format(self.path, block_size, block_count),
                                  shell=True)

            subprocess.check_call('mkfs.ext4 -b {} {}'.format(block_size,
                                                              self.path),
                                  shell=True)

            # debugfs is a e2fsprogs utility filesystem here used to populate
            # an image with an unprivileged user
            debugfs_write = 'debugfs -wR \"write {} {}\" {}'.format(
                    assets_tar.path, assets_tar.name, self.path)

            subprocess.check_call(debugfs_write, shell=True)

        except subprocess.CalledProcessError as e:
            raise TestBenchBase.Error(code=e.returncode, command=e.cmd)
