# This file is a part of Cougarnet, a tool for creating virtual networks.
#
# Copyright 2021-2022 Casey Deccio (casey@deccio.net)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.
#

'''A class for creating and managing a process that listens for incoming
requests for commands that require privileges and executes those commands.'''

import os
import socket
import subprocess

from cougarnet.globals import LIBEXEC_DIR
from cougarnet.sys_helper.manager import SysHelperManager
from cougarnet import util

SYSCMD_HELPER_SCRIPT = os.path.join(LIBEXEC_DIR, 'syscmd_helper')


def _setup_unix_sock(local_addr, remote_addr):
    '''Create and configured a UNIX domain socket of type SOCK_DGRAM with the
    given local and remote addresses.'''

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(local_addr)
    sock.connect(remote_addr)

    # set permissions on the socket
    cmd = ['chmod', '700', local_addr]
    subprocess.run(cmd, check=True)

    return sock


class SysCmdHelperManager(SysHelperManager):
    '''A class for creating and managing a process that listens for incoming
    requests for commands that require privileges and executes those
    commands.'''

    def __init__(self, remote_sock, local_sock, verbose=False):
        args = ['sudo', '-P', '-u', 'root',
                '-g', f'#{os.getegid()}', SYSCMD_HELPER_SCRIPT]

        if verbose:
            args.append('--verbose')
        args.append(remote_sock)
        super().__init__(*args)
        self.remote_sock_path = remote_sock
        self.local_sock_path = local_sock
        self.sock = None

    def start(self):
        '''Start the helper process.  If it started successfully, then also
        create and configure the socket that will be used for sending the
        commands to the process.  Return True if the process started properly
        and False otherwise.'''

        val = super().start()
        if val:
            self._setup_sock()
        return val

    def close(self):
        '''Stop the helper process, and clean up the socket.'''

        super().close()
        self._remove_sock()

    def _setup_sock(self):
        '''Create the socket that will be used for issuing commands to the
        privileged process.'''

        self.sock = _setup_unix_sock(
                self.local_sock_path, self.remote_sock_path)

    def _remove_sock(self):
        '''Remove the local socket, which was used for issuing commands to the
        privileged process.'''

        os.unlink(self.local_sock_path)

    def cmd(self, cmd):
        '''Issue the provided command, a list, to the privileged process, by
        sending it to the socket as a string with commas separating the command
        and its arguments.'''

        msg = util.list_to_csv_str(cmd)
        self.sock.send(msg.encode('utf8'))
        return self.sock.recv(1024).decode('utf-8')


class SysCmdHelperManagerStarted(SysCmdHelperManager):
    '''A subclass of SysCmdHelperManager that is used when the privileged
    process is already running and we simply want to connect to it to issue
    commands.'''

    def start(self):
        '''Create and configure the socket that will be used for sending the
        commands to the already-existing process, and return True.'''

        self._setup_sock()
        return True

    def close(self):
        '''Clean up the socket.'''

        self._remove_sock()
