#!/usr/bin/python3

from . import util

import argparse
import grp
import io
import json
import os
import pwd
import signal
import socket
import subprocess
import sys
import tempfile


def _apply_config(info):
    if info.get('hostname', None) is not None:
        cmd = ['hostname', info['hostname']]
        subprocess.run(cmd, check=True)

    if info.get('gw4', None) is not None:
        os.environ['COUGARNET_DEFAULT_GATEWAY_IPV4'] = info['gw4']
    if info.get('gw6', None) is not None:
        os.environ['COUGARNET_DEFAULT_GATEWAY_IPV6'] = info['gw6']
    native_apps = info.get('native_apps', True)

    if not native_apps:
        # enable iptables
        cmd = ['iptables', '-t', 'filter', '-I', 'INPUT', '-j', 'DROP']
        subprocess.run(cmd, check=True)
        cmd = ['ip6tables', '-t', 'filter', '-I', 'INPUT', '-j', 'DROP']
        subprocess.run(cmd, check=True)

    if info.get('ip_forwarding', False):
        cmd = ['sysctl', 'net.ipv4.ip_forward=1']
        subprocess.run(cmd, check=True)

    # bring lo up
    cmd = ['ip', 'link', 'set', 'lo', 'up']
    subprocess.run(cmd, check=True)

    for intf in info.get('interfaces', []):
        int_info = info['interfaces'][intf]
        if int_info.get('mac', None):
            # set MAC address, if specified
            cmd = ['ip', 'link', 'set', intf, 'address', int_info['mac']]
            subprocess.run(cmd, check=True)

        # bring link up
        cmd = ['ip', 'link', 'set', intf, 'up']
        subprocess.run(cmd, check=True)

        if not native_apps:
            # disable ARP
            cmd = ['ip', 'link', 'set', intf, 'arp', 'off']
            subprocess.run(cmd, check=True)

        # disable router solicitations
        cmd = ['sysctl', f'net.ipv6.conf.{intf}.router_solicitations=0']
        subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)

        # add each IP address
        for addr in int_info.get('addrs4', []) + \
                int_info.get('addrs6', []):
            cmd = ['ip', 'addr', 'add', addr, 'dev', intf]
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

        myintf = intf.replace('-', '_').upper()
        if int_info.get('vlan', None) is not None:
            os.environ[f'COUGARNET_VLAN_{myintf}'] = str(int_info['vlan'])
        if int_info.get('trunk', None) is not None:
            myintf = intf.replace('-', '_').upper()
            os.environ[f'COUGARNET_TRUNK_{myintf}'] = str(int_info['trunk']).upper()

def user_group_info(user):
    pwinfo = pwd.getpwnam(user)
    uid = pwinfo.pw_uid

    groups = [pwinfo.pw_gid]
    for gr in grp.getgrall():
        if user in gr.gr_mem:
            groups.append(gr.gr_gid)

    return uid, groups

def close_file_descriptors(exceptions):
    fds = [int(fd) for fd in os.listdir(f'/proc/{os.getpid()}/fd')]
    for fd in fds:
        if fd not in exceptions:
            try:
                os.close(fd)
            except OSError:
                pass

def sighup_handler(signum, frame):
    pass

def main():
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

    signal.signal(signal.SIGHUP, sighup_handler)

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
        util.remove_if_exists(os.environ['COUGARNET_MY_SOCK'])

        if args.user is not None:
            os.setgroups(groups)
            os.setuid(uid)

        # close all file descriptors, except stdin, stdout, stderr, and
        # sock.fileno()
        close_file_descriptors([0, 1, 2])

        if args.prog is not None:
            prog_args = args.prog.split('|')
            print(' '.join(prog_args))
            os.execvp(prog_args[0], prog_args)
        else:
            cmd = [os.environ.get('SHELL')]
            if sys.stdin.isatty():
                cmd.append('-i')
            os.execvp(cmd[0], cmd)

    except:
        import traceback
        import time
        traceback.print_exc()
        time.sleep(10)

if __name__ == '__main__':
    main()
