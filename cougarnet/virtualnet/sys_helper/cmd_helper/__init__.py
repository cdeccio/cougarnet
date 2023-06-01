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

from cougarnet.errors import CommandPrereqError, CommandExecError
from cougarnet.util import list_to_csv_str, csv_str_to_list

from .manager import SysCmdHelperManager, SysCmdHelperManagerStarted

sys_cmd_helper = None

def start_sys_cmd_helper(remote_sock_path, local_sock_path, verbose):
    global sys_cmd_helper

    assert sys_cmd_helper is None, \
        "sys_cmd_helper has already been initialized"

    sys_cmd_helper = SysCmdHelperManager(
            remote_sock_path, local_sock_path,
            verbose=verbose)

    return sys_cmd_helper.start()

def join_sys_cmd_helper(remote_sock_path, local_sock_path):
    global sys_cmd_helper

    assert sys_cmd_helper is None, \
        "sys_cmd_helper has already been initialized"

    sys_cmd_helper = SysCmdHelperManagerStarted(
            remote_sock_path, local_sock_path)

    return sys_cmd_helper.start()

def stop_sys_cmd_helper():
    assert sys_cmd_helper is not None, \
        "sys_cmd_helper has not been initialized"

    return sys_cmd_helper.close()

def sys_cmd(cmd, check=False):
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
            err = row[2]
        except IndexError:
            err = ''
        if not cmd_str:
            cmd_str = ' '.join(cmd)
            raise CommandPrereqError(f'Unable to execute command ' + \
                    f'"{cmd_str}": {err}')
        else:
            raise CommandExecError(f'Command failed: "{cmd_str}": {err}')
