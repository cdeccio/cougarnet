# This file is a part of Cougarnet, a tool for creating virtual networks on
# Linux.
#
# Copyright 2021-2022 Casey Deccio
#
# Cougarnet is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Cougarnet is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
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

def _apply_config(info):
    '''Apply the network configuration contained in the dictionary info.  Set
    the hostname, configure and set interfaces, and set environment variables
    related to VLANs and routes.'''

    if info.get('hostname', None) is not None:
        cmd = ['hostname', info['hostname']]
        subprocess.run(cmd, check=True)

    native_apps = info.get('native_apps', True)

    vlan_info = {}

    if not native_apps:
        # enable iptables
        cmd = ['iptables', '-t', 'filter', '-I', 'INPUT', '-j', 'DROP']
        subprocess.run(cmd, check=True)
        cmd = ['ip6tables', '-t', 'filter', '-I', 'INPUT', '-j', 'DROP']
        subprocess.run(cmd, check=True)

    if info.get('ip_forwarding', False):
        cmd = ['sysctl', 'net.ipv4.ip_forward=1']
        subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)

    # bring lo up
    cmd = ['ip', 'link', 'set', 'lo', 'up']
    subprocess.run(cmd, check=True)

    if not info.get('ipv6', True):
        cmd = ['sysctl', 'net.ipv6.conf.lo.disable_ipv6=1']
        subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)

    for intf in info.get('interfaces', []):
        int_info = info['interfaces'][intf]
        if int_info.get('mac_addr', None):
            # set MAC address, if specified
            cmd = ['ip', 'link', 'set', intf, 'address', int_info['mac_addr']]
            subprocess.run(cmd, check=True)

        # bring link up
        cmd = ['ip', 'link', 'set', intf, 'up']
        subprocess.run(cmd, check=True)

        if not native_apps:
            # disable ARP
            cmd = ['ip', 'link', 'set', intf, 'arp', 'off']
            subprocess.run(cmd, check=True)

        if not info.get('ipv6', True):
            cmd = ['sysctl', f'net.ipv6.conf.{intf}.disable_ipv6=1']
            subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)

        # disable router solicitations
        cmd = ['sysctl', f'net.ipv6.conf.{intf}.router_solicitations=0']
        subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)

        # add each IP address
        addrs = int_info.get('ipv4_addrs', [])[:]
        if info.get('ipv6', True):
            addrs += int_info.get('ipv6_addrs', [])

        for addr in addrs:
            if ':' in addr:
                cmd = ['ip', 'addr', 'add', addr, 'dev', intf]
            else:
                # set broadcast for IPv4 only
                cmd = ['ip', 'addr', 'add', addr, 'broadcast', '+', 'dev', intf]
            subprocess.run(cmd, check=True)

        cmd_suffix = []
        if int_info.get('bw', None) is not None:
            cmd_suffix += ['rate', int_info['bw']]
        if int_info.get('delay', None) is not None:
            cmd_suffix += ['delay', int_info['delay']]
        if int_info.get('loss', None) is not None:
            cmd_suffix += ['loss', int_info['loss']]
        if cmd_suffix:
            cmd = ['tc', 'qdisc', 'add', 'dev', intf, 'root', 'netem'] + \
                    cmd_suffix
            subprocess.run(cmd, check=True)

        if int_info.get('mtu', None) is not None:
            cmd = ['ip', 'link', 'set', intf, 'mtu', int_info['mtu']]
            subprocess.run(cmd, check=True)

        if int_info.get('vlan', None) is not None:
            vlan_info[intf] = f"vlan{int_info['vlan']}"
        elif int_info.get('trunk', None):
            vlan_info[intf] = 'trunk'
        else:
            pass

    if vlan_info:
        os.environ['COUGARNET_VLAN'] = json.dumps(vlan_info)

    routes = info.get('routes', [])
    if not info.get('ipv6', True):
        routes = [r for r in routes if ':' not in r[0]]
    os.environ['COUGARNET_ROUTES'] = json.dumps(routes)

    if native_apps:
        for prefix, intf, next_hop in routes:
            cmd = ['ip', 'route', 'add', prefix]
            if next_hop is not None:
                cmd += ['via', next_hop]
            cmd += ['dev', intf]
            subprocess.run(cmd, check=True)

def user_group_info(user):
    '''Return the user ID and group ID(s) associated with the specified
    user.'''

    pwinfo = pwd.getpwnam(user)
    uid = pwinfo.pw_uid

    groups = [pwinfo.pw_gid]
    for gr in grp.getgrall():
        if user in gr.gr_mem:
            groups.append(gr.gr_gid)

    return uid, groups

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
    parser.add_argument('--prog', '-p',
            action='store', type=str, default=None,
            help='Path to program that should be executed at start')
    parser.add_argument('--mount-sys',
            action='store_const', const=True, default=False,
            help='Whether or not to mount sysfs on /sys')
    parser.add_argument('--user', '-u',
            type=str, action='store', default=None,
            help='Change effective user')
    parser.add_argument('config_file',
            type=argparse.FileType('r'), action='store',
            help='File containing the network configuration for host')
    parser.add_argument('comm_sock',
            action='store', type=str, default=None,
            help='Path to UNIX socket with which we communicate with the' + \
                    'coordinating process')
    parser.add_argument('my_sock',
            action='store', type=str, default=None,
            help='Path to UNIX socket with which with coordinating process' + \
                    'communicattes with us')

    try:
        args = parser.parse_args(sys.argv[1:])

        os.environ['COUGARNET_MY_SOCK'] = args.my_sock
        os.environ['COUGARNET_COMM_SOCK'] = args.comm_sock

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        sock.bind(os.environ['COUGARNET_MY_SOCK'])

        # make the socket file readable by everyone, so the other process can
        # communicate back to us
        cmd = ['chmod', '777', os.environ['COUGARNET_MY_SOCK']]
        subprocess.run(cmd, check=True)

        # Tell the coordinating process that the the process has started--and
        # thus that the namespaces have been created
        sock.connect(os.environ['COUGARNET_COMM_SOCK'])
        pid = os.getpid()
        sock.send(f'{pid}'.encode('utf-8'))

        # wait for UDP datagram from coordinating process to let us know that
        # interfaces have been added and configured
        sock.recv(1)

        config = json.loads(args.config_file.read())
        args.config_file.close()
        _apply_config(config)

        if args.mount_sys:
            cmd = ['mount', '-t', 'sysfs', '/sys', '/sys']
            subprocess.run(cmd, check=True)

        if args.hosts_file is not None:
            cmd = ['mount', '-o', 'bind', args.hosts_file, '/etc/hosts']
            subprocess.run(cmd, check=True)

        if args.user is not None:
            uid, groups = user_group_info(args.user)

        # tell the coordinating process that everything is ready to go
        sock.send(b'\x00')

        # wait for return packet indicating that we can start
        sock.recv(1)

        # close socket and remove the associated file
        sock.close()
        os.unlink(os.environ['COUGARNET_MY_SOCK'])

        if args.user is not None:
            os.setgroups(groups)
            os.setuid(uid)

        # close all file descriptors, except stdin, stdout, stderr, and
        # sock.fileno()
        close_file_descriptors([0, 1, 2])

        if args.prog is not None:
            prog_args = args.prog.split('|')
            os.execvp(prog_args[0], prog_args)
        else:
            cmd = [os.environ.get('SHELL')]
            if sys.stdin.isatty():
                cmd.append('-i')
            os.execvp(cmd[0], cmd)

    except Exception:
        traceback.print_exc()
        time.sleep(10)

if __name__ == '__main__':
    main()
