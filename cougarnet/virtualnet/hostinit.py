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
Functions called by virtual hosts to initialize them for use in part of a
virtual network.
'''

import argparse
import grp
import json
import os
import pwd
import socket
import subprocess
import sys
import time
import traceback

from cougarnet.sys_helper.manager import SysCmdHelperManagerStarted
from cougarnet.virtualnet.errors import StartupError

#XXX show debug to terminal until very end

#XXX this code is in three places; consolidate it
sys_cmd_helper = None
def sys_cmd(cmd, check=False):
    status = sys_cmd_helper.cmd(cmd)
    if not status.startswith('0,') and check:
        try:
            err = status.split(',', maxsplit=1)[1]
        except ValueError:
            err = ''
        raise StartupError(err)

def _apply_config(info):
    '''Apply the network configuration contained in the dictionary info.  Set
    the hostname, configure and set interfaces, and set environment variables
    related to VLANs and routes.'''

    hostname = info['hostname']
    pid = str(os.getpid())

    if info.get('hostname', None) is not None:
        cmd = ['set_hostname', pid, hostname]
        sys_cmd(cmd, check=True)

    native_apps = info.get('native_apps', True)

    vlan_info = {}

    if not native_apps:
        # enable iptables
        cmd = ['set_iptables_drop', pid]
        sys_cmd(cmd, check=True)
        cmd = ['set_ip6tables_drop', pid]
        sys_cmd(cmd, check=True)

    if info.get('ip_forwarding', False):
        # enable iptables
        cmd = ['enable_ip_forwarding', pid]
        sys_cmd(cmd, check=True)
        cmd = ['enable_ip6_forwarding', pid]
        sys_cmd(cmd, check=True)

    # bring lo up
    cmd = ['set_lo_up', pid]
    sys_cmd(cmd, check=True)

    if not info.get('ipv6', True):
        cmd = ['disable_lo_ipv6', pid]
        sys_cmd(cmd, check=True)

    for intf in info.get('interfaces', []):
        int_info = info['interfaces'][intf]
        if int_info.get('mac_addr', None):
            # set MAC address, if specified
            cmd = ['set_link_mac_addr', intf, int_info['mac_addr']]
            sys_cmd(cmd, check=True)

        # bring link up
        cmd = ['set_link_up', intf]
        sys_cmd(cmd, check=True)

        if not native_apps:
            # disable ARP
            cmd = ['disable_arp', intf]
            sys_cmd(cmd, check=True)

        if not info.get('ipv6', True):
            cmd = ['disable_ipv6', intf]
            sys_cmd(cmd, check=True)

        # disable router solicitations
        cmd = ['disable_router_solicitations', intf]
        sys_cmd(cmd, check=True)

        # add each IP address
        addrs = int_info.get('ipv4_addrs', [])[:]
        if info.get('ipv6', True):
            addrs += int_info.get('ipv6_addrs', [])

        for addr in addrs:
            cmd = ['set_link_ip_addr', intf, addr]
            sys_cmd(cmd, check=True)

        cmd_suffix = []
        if int_info.get('bw', None) is not None:
            cmd_suffix += ['rate', int_info['bw']]
        if int_info.get('delay', None) is not None:
            cmd_suffix += ['delay', int_info['delay']]
        if int_info.get('loss', None) is not None:
            cmd_suffix += ['loss', int_info['loss']]
        if cmd_suffix:
            cmd = ['set_link_attrs', intf] + cmd_suffix
            sys_cmd(cmd, check=True)

        if int_info.get('mtu', None) is not None:
            cmd = ['set_link_mtu', intf, mtu]
            sys_cmd(cmd, check=True)

        if int_info.get('vlan', None) is not None:
            vlan_info[intf] = f"vlan{int_info['vlan']}"
        elif int_info.get('trunk', None):
            vlan_info[intf] = 'trunk'
        else:
            pass

    if vlan_info:
        os.environ['COUGARNET_VLAN'] = json.dumps(vlan_info)

    if info.get('int_to_sock', None) is not None:
        os.environ['COUGARNET_INT_TO_SOCK'] = \
                json.dumps(info['int_to_sock'])

    routes = info.get('routes', [])
    if not info.get('ipv6', True):
        routes = [r for r in routes if ':' not in r[0]]
    os.environ['COUGARNET_ROUTES'] = json.dumps(routes)

    if native_apps:
        for prefix, intf, next_hop in routes:
            if next_hop is None:
                next_hop = ''
            cmd = ['add_route', pid, prefix, intf, next_hop]
            sys_cmd(cmd, check=True)

def close_file_descriptors():
    '''Close all open file descriptors except those specified.'''

    fds = [int(fd) for fd in os.listdir(f'/proc/{os.getpid()}/fd')]
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass

def _update_environment_sudo():
    if 'SUDO_USER' in os.environ:
        os.environ['USER'] = os.environ['SUDO_USER']
        del os.environ['SUDO_USER']

    if 'SUDO_GROUP' in os.environ:
        os.environ['GROUP'] = os.environ['SUDO_GROUP']
        del os.environ['SUDO_GROUP']

    if 'LOGNAME' in os.environ:
        os.environ['LOGNAME'] = os.environ['USER']

    try:
        del os.environ['SUDO_UID']
    except KeyError:
        pass

    try:
        del os.environ['SUDO_GID']
    except KeyError:
        pass

    try:
        del os.environ['SUDO_COMMAND']
    except KeyError:
        pass

def main():
    '''Parse command-line arguments, synchronize with virtual network manager,
    apply network configuration, and set appropriate environment variables.'''

    parser = argparse.ArgumentParser()
    parser.add_argument('--hosts-file', '-f',
            action='store', type=str, default=None,
            help='Specify the hosts file')
    parser.add_argument('--mount-sys',
            action='store_const', const=True, default=False,
            help='Whether or not to mount sysfs on /sys')
    parser.add_argument('config_file',
            type=argparse.FileType('r'), action='store',
            help='File containing the network configuration for host')
    parser.add_argument('sys_cmd_helper_sock_remote',
            type=str, action='store',
            help='The remote "address" (path) of a UNIX domain socket to ' + \
                    'which commands requiring privileges are executed on ' + \
                    'behalf of this process.')
    parser.add_argument('sys_cmd_helper_sock_local',
            type=str, action='store',
            help='The local "address" (path) of a UNIX domain socket to ' + \
                    'which commands requiring privileges are executed on ' + \
                    'behalf of this process.')
    parser.add_argument('comm_sock_remote',
            action='store', type=str, default=None,
            help='Remote "address" (path) for UNIX domain socket with which we ' + \
                    'communicate with the coordinating process')
    parser.add_argument('comm_sock_local',
            action='store', type=str, default=None,
            help='Local "address" (path) for UNIX domain socket with which we ' + \
                    'communicate with the coordinating process')
    parser.add_argument('prog',
            action='store', type=str, default=None,
            help='Path to program that should be executed at start')

    try:
        args = parser.parse_args(sys.argv[1:])

        _update_environment_sudo()

        comm_sock_paths = {
                'local': args.comm_sock_local,
                'remote': args.comm_sock_remote
                }
        os.environ['COUGARNET_COMM_SOCK'] = json.dumps(comm_sock_paths)

        global sys_cmd_helper
        sys_cmd_helper = SysCmdHelperManagerStarted(
                args.sys_cmd_helper_sock_remote, args.sys_cmd_helper_sock_local)
        sys_cmd_helper.start()

        comm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        comm_sock.bind(comm_sock_paths['local'])
        comm_sock.connect(comm_sock_paths['remote'])

        cmd = ['chmod', '700', comm_sock_paths['local']]
        subprocess.run(cmd, check=True)

        # Tell the coordinating process that the the process has started--and
        # thus that the namespaces have been created
        pid = os.getpid()
        comm_sock.send(f'{pid}'.encode('utf-8'))

        # wait for UDP datagram from coordinating process to let us know that
        # interfaces have been added and configured
        comm_sock.recv(1)

        config = json.loads(args.config_file.read())
        args.config_file.close()
        _apply_config(config)

        if args.mount_sys:
            cmd = ['mount_sys', pid]
            sys_cmd(cmd, check=True)

        if args.hosts_file is not None:
            cmd = ['mount_hosts', pid, args.hosts_file]
            sys_cmd(cmd, check=True)

        # tell the coordinating process that everything is ready to go
        comm_sock.send(b'\x00')

        # wait for return packet indicating that we can start
        comm_sock.recv(1)

        # close socket and remove the associated file
        comm_sock.close()
        os.unlink(comm_sock_paths['local'])

        # close all file descriptors, except stdin, stdout, stderr
        #close_file_descriptors([0, 1, 2])
        close_file_descriptors()

        #XXX maybe put prog in config file?
        prog_args = args.prog.split('|')
        os.execvp(prog_args[0], prog_args)

    except Exception:
        traceback.print_exc()
        time.sleep(10)

if __name__ == '__main__':
    main()
