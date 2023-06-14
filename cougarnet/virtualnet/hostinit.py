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
import json
import os
import socket
import subprocess
import sys

from .sys_helper.cmd_helper import \
        join_sys_cmd_helper, stop_sys_cmd_helper, sys_cmd

#XXX show debug to terminal until very end

def _apply_config(info, env):
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
        cmd = ['set_iptables_drop', pid, '']
        sys_cmd(cmd, check=True)
        cmd = ['set_ip6tables_drop', pid, '']
        sys_cmd(cmd, check=True)

    if info.get('ip_forwarding', False):
        # enable iptables
        cmd = ['enable_ip_forwarding', pid]
        sys_cmd(cmd, check=True)
        cmd = ['enable_ip6_forwarding', pid]
        sys_cmd(cmd, check=True)

    if not info.get('ipv6', True):
        cmd = ['disable_lo_ipv6', pid]
        sys_cmd(cmd, check=True)

    # bring lo up
    cmd = ['set_lo_up', pid]
    sys_cmd(cmd, check=True)

    for intf in info.get('interfaces', []):
        int_info = info['interfaces'][intf]
        if int_info.get('mac_addr', None):
            # set MAC address, if specified
            cmd = ['set_link_mac_addr', intf, int_info['mac_addr']]
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

        # bring link up
        cmd = ['set_link_up', intf]
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
            cmd = ['set_link_mtu', intf, int_info['mtu']]
            sys_cmd(cmd, check=True)

        if int_info.get('vlan', None) is not None:
            vlan_info[intf] = f"vlan{int_info['vlan']}"
        elif int_info.get('trunk', None):
            vlan_info[intf] = 'trunk'
        else:
            pass

    if vlan_info:
        env['COUGARNET_VLAN'] = json.dumps(vlan_info)

    if info.get('int_to_sock', None) is not None:
        env['COUGARNET_INT_TO_SOCK'] = \
                json.dumps(info['int_to_sock'])

    routes = info.get('routes', [])
    if not info.get('ipv6', True):
        routes = [r for r in routes if ':' not in r[0]]
    env['COUGARNET_ROUTES'] = json.dumps(routes)

    if native_apps:
        for prefix, intf, next_hop in routes:
            if next_hop is None:
                next_hop = ''
            cmd = ['add_route', pid, prefix, intf, next_hop]
            sys_cmd(cmd, check=True)

def close_file_descriptors(exceptions):
    '''Close all open file descriptors except those specified.'''

    fds = [int(fd) for fd in os.listdir(f'/proc/{os.getpid()}/fd')]
    for fd in fds:
        if fd not in exceptions:
            try:
                os.close(fd)
            except OSError:
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
    parser.add_argument('--vty-socket', action='store',
            type=str, default=None,
            help='The directory for the FRR vty socket')
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

    args = parser.parse_args(sys.argv[1:])

    if os.geteuid() == 0:
        sys.stderr.write('Please run this program as a non-privileged user.\n')
        sys.exit(1)

    env = {}

    comm_sock_paths = {
            'local': args.comm_sock_local,
            'remote': args.comm_sock_remote
            }
    env['COUGARNET_COMM_SOCK'] = json.dumps(comm_sock_paths)

    if args.vty_socket is not None:
        env['COUGARNET_VTY_SOCK'] = args.vty_socket

    if not join_sys_cmd_helper(
            args.sys_cmd_helper_sock_remote, args.sys_cmd_helper_sock_local):
        sys.stderr.write('Could not join system command helper!\n')
        sys.exit(1)

    comm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
    comm_sock.bind(comm_sock_paths['local'])
    comm_sock.connect(comm_sock_paths['remote'])

    cmd = ['chmod', '700', comm_sock_paths['local']]
    subprocess.run(cmd, check=True)

    sys_cmd_helper_sock_paths = {
            'local': args.sys_cmd_helper_sock_local,
            'remote': args.sys_cmd_helper_sock_remote
            }
    env['COUGARNET_SYS_CMD_HELPER_SOCK'] = json.dumps(sys_cmd_helper_sock_paths)

    # Tell the coordinating process that the the process has started--and
    # thus that the namespaces have been created
    pid = os.getpid()
    comm_sock.send(f'{pid}'.encode('utf-8'))

    # wait for UDP datagram from coordinating process to let us know that
    # interfaces have been added and configured
    comm_sock.recv(1)

    config = json.loads(args.config_file.read())
    args.config_file.close()
    _apply_config(config, env)

    if args.mount_sys:
        cmd = ['mount_sys', pid]
        sys_cmd(cmd, check=True)

    if args.hosts_file is not None:
        cmd = ['mount_hosts', pid, args.hosts_file]
        sys_cmd(cmd, check=True)

    # clean up sys_cmd_helper
    stop_sys_cmd_helper()

    # tell the coordinating process that everything is ready to go
    comm_sock.send(b'\x00')

    # wait for return packet indicating that we can start
    comm_sock.recv(1)

    # close socket and remove the associated file
    comm_sock.close()
    os.unlink(comm_sock_paths['local'])

    # close all file descriptors, except stderr
    close_file_descriptors([2])

    prog_args = args.prog.split('|')
    os.execve(prog_args[0], prog_args, env)

if __name__ == '__main__':
    main()
