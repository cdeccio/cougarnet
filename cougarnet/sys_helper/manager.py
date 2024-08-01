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

'''Class used to create and manage processes running as root.  Processes
running as unprivileged users, interact with these processes for help with
things for which they need privileges.'''

import logging
import os
import signal
import sys

LIBEXEC_DIR = os.path.join(sys.prefix, 'libexec', 'cougarnet')

logger = logging.getLogger(__name__)


def raise_interrupt(signum, frame):
    '''When a given signal is received, raise KeyboardInterrupt.'''

    raise KeyboardInterrupt()


class SysHelperManager:
    '''A class for creating and managing a process running as a privileged
    user.'''

    def __init__(self, *args):
        self._cmd = args
        self._pipe_fd = None

    def start(self):
        '''Create the new process by calling fork.  Create two pipes, one for
        letting the helper know when it should terminate (upon termination of
        parent process) and one for communicating back to the parent that it
        has started successfully. Return True  if the process starts up
        successfully and False otherwise.'''

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

            logger.debug(' '.join(self._cmd))
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
        '''Explicitly close the pipe on which the child is listening.  This
        will make the child exit.'''

        os.close(self._pipe_fd)
