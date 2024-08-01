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

'''
Various utility functions for the cmd_helper module.
'''

import os
import subprocess
import sys

from cougarnet.errors import SysCmdError, CommandPrereqError, CommandExecError
from cougarnet.util import csv_str_to_list

from .manager import SysCmdHelperManager, SysCmdHelperManagerStarted

sys_cmd_helper = None


def start_sys_cmd_helper(remote_sock_path, local_sock_path, verbose):
    '''Instantiate a SysCmdHelperManager, which will start the privileged
    process that will listen for commands using the remote_sock_path
    provided.  Assign that object to the global variable sys_cmd_helper, so it
    can be used for running commands using sys_cmd().'''

    global sys_cmd_helper

    assert sys_cmd_helper is None, \
        "sys_cmd_helper has already been initialized"

    sys_cmd_helper = SysCmdHelperManager(
            remote_sock_path, local_sock_path,
            verbose=verbose)

    return sys_cmd_helper.start()


def join_sys_cmd_helper(remote_sock_path, local_sock_path,
                        add_pid_for_netns=False):
    '''Instantiate a SysCmdHelperManagerStarted, which will setup sockets for
    communication with an already running privileged process, i.e., associated
    with a SysCmdHelperManager instance.  Assign that object to the global
    variable sys_cmd_helper, so it can be used for running commands using
    sys_cmd().  If add_pid_for_netns is True, then also add the pid of this
    process to the approved list of pids and namespaces known to the privileged
    process.'''

    global sys_cmd_helper

    assert sys_cmd_helper is None, \
        "sys_cmd_helper has already been initialized"

    sys_cmd_helper = SysCmdHelperManagerStarted(
            remote_sock_path, local_sock_path)

    sys_cmd_helper.start()
    if add_pid_for_netns:
        sys_cmd(['add_pid_for_netns', str(os.getpid())], check=True)
    return True


def stop_sys_cmd_helper():
    '''Call close() on sys_cmd_helper, which will terminate the privileged
    process and clean up the sockets used for communication.'''

    global sys_cmd_helper

    assert sys_cmd_helper is not None, \
        "sys_cmd_helper has not been initialized"

    sys_cmd_helper.close()
    sys_cmd_helper = None


def sys_cmd(cmd, check=False):
    '''Send a command to the privileged process by calling sys_cmd_helper.cmd()
    on cmd, which is a list consisting of the command and its arguments.  If
    the command fails, and check is True, then raise CommandPrereqError or
    CommandExecError, depending on the nature of the error.'''

    assert sys_cmd_helper is not None, \
        "sys_cmd_helper must be initialized before sys_cmd() can be called"

    status = sys_cmd_helper.cmd(cmd).strip()
    if not status.startswith('0,') and check:
        row = csv_str_to_list(status)
        try:
            exit_code = int(row[0])
        except ValueError:
            exit_code = None
        try:
            cmd_str = row[1]
        except IndexError:
            cmd_str = ''
        try:
            err = row[2].strip()
        except IndexError:
            err = ''
        if not cmd_str:
            cmd_str = ' '.join(cmd)
            raise CommandPrereqError('Unable to execute command ' +
                                     f'"{cmd_str}": {err}')
        else:
            raise CommandExecError(f'Command failed: "{cmd_str}": {err}')


def sys_cmd_pid(cmd, check=False):
    '''Insert the pid of this process into cmd, and call sys_cmd() on the
    resulting command.'''

    pid = str(os.getpid())
    return sys_cmd([cmd[0]] + [pid] + cmd[1:], check=check)


def sys_cmd_with_cleanup(cmd, cleanup_cmds, check=False, default_yes=False):
    '''Call sys_cmd() with cmd as an argument.  If an exception is raised
    (i.e., because the command fails), then run each of the commands specified
    in the list cleanup_cmds and try again.'''

    try:
        sys_cmd(cmd, check)
    except SysCmdError as e:
        n = len(cleanup_cmds)
        sys.stderr.write('%s\n' % e)
        sys.stderr.write(f'The following {n} command(s) should ' +
                         'be executed before trying again.\n')
        for i, cleanup_cmd in enumerate(cleanup_cmds):
            cmd_str = ' '.join(cleanup_cmd)
            sys.stderr.write(f'  {i+1}: {cmd_str}\n')
            if default_yes:
                sys.stderr.write('     Run? [(y)/n] ')
            else:
                sys.stderr.write('     Run? [y/(n)] ')
            sys.stderr.flush()
            ans = sys.stdin.readline().strip()
            if ans.lower() in ('y', 'yes') or \
                    (default_yes and not ans):
                subprocess.run(cleanup_cmd, check=False)

        # try to run the original command again
        sys_cmd(cmd, check)
