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

import csv
import io
import os
import signal
import socket
import subprocess
import sys
import tempfile

LIBEXEC_DIR = os.path.join(sys.prefix, 'libexec', 'cougarnet')
SYSCMD_HELPER_SCRIPT = os.path.join(LIBEXEC_DIR, 'syscmd_helper')
RAWPKT_HELPER_SCRIPT = os.path.join(LIBEXEC_DIR, 'rawpkt_helper')

def raise_interrupt(signum, frame):
    raise KeyboardInterrupt()

def _setup_unix_sock(local_addr, remote_addr):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(local_addr)
    sock.connect(remote_addr)

    # set permissions on the socket
    cmd = ['chmod', '700', local_addr]
    subprocess.run(cmd, check=True)

    return sock

class SysHelperManager:
    _cmd_base = ()

    def __init__(self, *args):
        self._cmd = self._cmd_base + args
        self._pipe_fd = None

    def start(self):
        # We use two pipes: one for letting the helper know that the cougarnet
        # process has died, so it can terminate as well; and one for the helper
        # to communicate back to the cougarnet process that it is up and
        # running.  The second pipe will be closed once the "alive" message has
        # been received.
        p2c_readfd, p2c_writefd = os.pipe()
        c2p_readfd, c2p_writefd = os.pipe()
        pid = os.fork()

        if pid == 0:
            # This is the child process, which will become the helper process
            # through the use of exec, once it is properly prepared.

            # set group id, so we don't get interrupts
            os.setpgid(0, 0)

            # Close the ends of the pipe that will not be used by this process.
            os.close(p2c_writefd)
            os.close(c2p_readfd)

            # Duplicate p2c_readfd on stdin
            os.dup2(p2c_readfd, 0)
            os.close(p2c_readfd)

            # Duplicate c2p_writefd on stdout
            os.dup2(c2p_writefd, 1)
            os.close(c2p_writefd)

            #sys.stderr.write(str(list(self._cmd)) + '\n')
            os.execvp(self._cmd[0], self._cmd)
            sys.exit(1)

        # Close the ends of the pipe that will not be used by this process.
        os.close(p2c_readfd)
        os.close(c2p_writefd)

        # Use ALRM to let us know when we've waited too long for the child
        # process to become ready.
        old_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, raise_interrupt)
        signal.alarm(3)
        try:
            if len(os.read(c2p_readfd, 1)) < 1:
                # read resulted in error
                os.close(p2c_writefd)
                return False
        except KeyboardInterrupt:
            # Timeout (ALRM signal was received)
            os.close(p2c_writefd)
            return False
        finally:
            # Reset alarm, restore previous ALRM handler, and close
            # c2p_readfd, which is no longer needed.
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
            os.close(c2p_readfd)

        self._pipe_fd = p2c_writefd
        return True

    def close(self):
        os.close(self._pipe_fd)

class SysCmdHelperManager(SysHelperManager):
    _cmd_base = ('sudo', '-E', SYSCMD_HELPER_SCRIPT)

    def __init__(self, remote_sock, local_sock):
        super().__init__(remote_sock)
        self.remote_sock_path = remote_sock
        self.local_sock_path = local_sock
        self.sock = None

    def start(self):
        val = super().start()
        if val:
            self._setup_sock()
        return val

    def _setup_sock(self):
        self.sock = _setup_unix_sock(
                self.local_sock_path, self.remote_sock_path)

    def cmd(self, cmd):
        s = io.StringIO()
        csv_writer = csv.writer(s)
        csv_writer.writerow(cmd)
        msg = s.getvalue().encode('utf-8')
        self.sock.send(msg)
        return self.sock.recv(1024).decode('utf-8')

class SysCmdHelperManagerStarted(SysCmdHelperManager):
    def start(self):
        self._setup_sock()

class RawPktHelperManager(SysHelperManager):
    def __init__(self, namespace, *ints):
        super().__init__('ip', 'netns', 'exec', namespace,
                RAWPKT_HELPER_SCRIPT, *ints)