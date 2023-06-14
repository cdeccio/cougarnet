# This file is a part of Cougarnet, a tool for creating virtual networks.
#
# Copyright 2023 Casey Deccio (casey@deccio.net)
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
A module containing a class, class methods, and functions for calling sys_cmd()
and sys_cmd_with_cleanup().
'''

import os

from cougarnet.sys_helper.cmd_helper.cmd_helper import \
        RUN_NETNS_DIR, FRR_CONF_DIR, FRR_RUN_DIR, \
        FRR_ZEBRA_PID_FILE, FRR_RIPD_PID_FILE, FRR_RIPNGD_PID_FILE, \
        FRR_ZEBRA_CONF_FILE, FRR_RIPD_CONF_FILE, FRR_RIPNGD_CONF_FILE
from cougarnet.sys_helper.cmd_helper import sys_cmd, sys_cmd_with_cleanup

class CommandWrapper:
    '''
    A class containing class methods for calling sys_cmd_with_cleanup() for
    certain commands.
    '''

    @classmethod
    def add_link_veth(cls, intf1, intf2):
        '''Call sys_cmd_with_cleanup(['add_link_veth', ...]) with the
        appropriate cleanup commands.'''

        cmd = ['add_link_veth', intf1, intf2]
        cleanup_cmds = [['sudo', 'ip', 'link', 'del', intf1]]
        if intf2:
            cleanup_cmds.append(['sudo', 'ip', 'link', 'del', intf2])
        sys_cmd_with_cleanup(cmd, cleanup_cmds, check=True)

    @classmethod
    def add_link_bridge(cls, br):
        '''Call sys_cmd_with_cleanup(['add_link_bridge', ...]) with the
        appropriate cleanup commands.'''

        cmd = ['add_link_bridge', br]
        cleanup_cmds = [['sudo', 'ip', 'link', 'del', br]]
        sys_cmd_with_cleanup(cmd, cleanup_cmds, check=True)

    @classmethod
    def ovs_add_bridge(cls, br):
        '''Call sys_cmd_with_cleanup(['ovs_add_bridge', ...]) with the
        appropriate cleanup commands.'''

        cmd = ['ovs_add_bridge', br]
        cleanup_cmds = [['sudo', 'ovs-vsctl', 'del-br', br]]
        sys_cmd_with_cleanup(cmd, cleanup_cmds, check=True)

    @classmethod
    def add_link_vlan(cls, phys_intf, intf, vlan):
        '''Call sys_cmd_with_cleanup(['add_link_vlan', ...]) with the
        appropriate cleanup commands.'''

        cmd = ['add_link_vlan', phys_intf, intf, vlan]
        cleanup_cmds = [['sudo', 'ip', 'link', 'del', intf]]
        sys_cmd_with_cleanup(cmd, cleanup_cmds, check=True)

    @classmethod
    def add_netns(cls, hostname):
        '''Call sys_cmd_with_cleanup(['add_netns', ...]) with the
        appropriate cleanup commands.'''

        cmd = ['add_netns', hostname]
        cleanup_cmds = [
                ['sudo', 'umount', os.path.join(RUN_NETNS_DIR, hostname)],
                ['sudo', 'umount', os.path.join(RUN_NETNS_DIR, hostname)],
                ['sudo', 'rm', '-rf', \
                os.path.join(RUN_NETNS_DIR, hostname)]]
        sys_cmd_with_cleanup(cmd, cleanup_cmds, check=True)

    @classmethod
    def start_zebra(cls, hostname):
        '''Call sys_cmd_with_cleanup(['start_zebra', ...]) with the
        appropriate cleanup commands.'''

        pid_file_path = os.path.join(FRR_RUN_DIR,
                hostname, FRR_ZEBRA_PID_FILE)
        conf_file_path = os.path.join(FRR_CONF_DIR,
                hostname, FRR_ZEBRA_CONF_FILE)

        cmd = ['start_zebra', hostname]
        cleanup_cmds = [
                ['sudo', 'pkill', '--signal', 'TERM',
                    '-F', pid_file_path],
                ['sudo', 'rm', conf_file_path]]
        sys_cmd_with_cleanup(cmd, cleanup_cmds, check=True)

    @classmethod
    def start_ripd(cls, hostname, *ints):
        '''Call sys_cmd_with_cleanup(['start_ripd', ...]) with the
        appropriate cleanup commands.'''

        pid_file_path = os.path.join(FRR_RUN_DIR,
                hostname, FRR_RIPD_PID_FILE)
        conf_file_path = os.path.join(FRR_CONF_DIR,
                hostname, FRR_RIPD_CONF_FILE)

        cmd = ['start_ripd', hostname] + [i for i in ints]
        cleanup_cmds = [
                ['sudo', 'pkill', '--signal', 'TERM',
                    '-F', pid_file_path],
                ['sudo', 'rm', conf_file_path]]
        sys_cmd_with_cleanup(cmd, cleanup_cmds, check=True)

    @classmethod
    def start_ripngd(cls, hostname, *ints):
        '''Call sys_cmd_with_cleanup(['start_ripngd', ...]) with the
        appropriate cleanup commands.'''

        pid_file_path = os.path.join(FRR_RUN_DIR,
                hostname, FRR_RIPNGD_PID_FILE)
        conf_file_path = os.path.join(FRR_CONF_DIR,
                hostname, FRR_RIPNGD_CONF_FILE)

        cmd = ['start_ripngd', hostname] + [i for i in ints]
        cleanup_cmds = [
                ['sudo', 'pkill', '--signal', 'TERM',
                    '-F', pid_file_path],
                ['sudo', 'rm', conf_file_path]]
        sys_cmd_with_cleanup(cmd, cleanup_cmds, check=True)

def run_cmd(cmd, *args):
    '''Call the class method associated with cmd, if there is one; otherwise
    call sys_cmd(['cmd', ...]).'''

    if hasattr(CommandWrapper, cmd):
        getattr(CommandWrapper, cmd)(*args)
    else:
        cmd = (cmd,) + args
        sys_cmd(cmd, check=True)
