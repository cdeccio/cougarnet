#!/usr/bin/python3

import argparse
import grp
import os
import pwd
import signal
import socket
import subprocess
import sys
import tempfile

def apply_config(fh):
    hostinfo = fh.readline().strip()
    hostname, type, gw4, gw6, commsock_file = hostinfo.split(',')

    cmd = ['hostname', hostname]
    subprocess.run(cmd, check=True)

    for line in fh.readlines():
        line = line.strip()
        parts = line.split(',')
        intf = parts[0]
        addrs = parts[2:]

        if len(parts) > 1:
            mac = parts[1]
            # set MAC address, if specified
            if mac:
                cmd = ['ip', 'link', 'set', intf, 'address', mac]
                subprocess.run(cmd, check=True)

        # bring link up
        cmd = ['ip', 'link', 'set', intf, 'up']
        subprocess.run(cmd, check=True)

        # disable router solicitations
        cmd = ['sysctl', f'net.ipv6.conf.{intf}.router_solicitations=0']
        subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)

        #TODO
        # disable ARP
        #cmd = ['ip', 'link', 'set', intf, 'arp', 'off']
        #subprocess.run(cmd, check=True)

        # add each IP address
        for addr in addrs:
            cmd = ['ip', 'addr', 'add', addr, 'dev', intf]
            subprocess.run(cmd, check=True)

    if commsock_file:
        os.environ['COUGARNET_COMM_SOCK'] = commsock_file

def sighup_handler(signum, frame):
    pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--disable-native-stack', '-n',
            action='store_const', const=True, default=False,
            help='Disable the native network stack')
    parser.add_argument('--hosts-file', '-f',
            action='store', type=str, default=None,
            help='Specify the hosts file')
    parser.add_argument('--prog', '-p',
            action='store', type=str, default=None,
            help='Path to program that should be executed at start')
    parser.add_argument('--user', '-u',
            type=str, action='store', default=None,
            help='Change effective user')
    parser.add_argument('pid_file',
            type=argparse.FileType('w'), action='store',
            help='File to which the PID should be written')
    parser.add_argument('config_file',
            type=argparse.FileType('r'), action='store',
            help='File containing the network configuration for host')

    signal.signal(signal.SIGHUP, sighup_handler)

    try:
        args = parser.parse_args(sys.argv[1:])
        args.pid_file.write(f'{os.getpid()}')
        args.pid_file.close()

        # wait for SIGHUP to let us know that the interfaces have been added
        signal.pause()

        apply_config(args.config_file)

        cmd = ['mount', '-t', 'sysfs', '/sys', '/sys']
        subprocess.run(cmd, check=True)

        if args.hosts_file is not None:
            cmd = ['mount', '-o', 'bind', args.hosts_file, '/etc/hosts']
            subprocess.run(cmd, check=True)

        if args.disable_native_stack:
            cmd = ['iptables', '-t', 'filter', '-I', 'INPUT', '-j', 'DROP']
            subprocess.run(cmd, check=True)
            cmd = ['ip6tables', '-t', 'filter', '-I', 'INPUT', '-j', 'DROP']
            subprocess.run(cmd, check=True)

        if args.user is not None:
            pwinfo = pwd.getpwnam(args.user)
            groups = [pwinfo.pw_gid]
            for gr in grp.getgrall():
                if args.user in gr.gr_mem:
                    groups.append(gr.gr_gid)
            uid = pwinfo.pw_uid

        cmd = ['rm', args.pid_file.name]
        subprocess.run(cmd, check=True)

        if args.user is not None:
            os.setgroups(groups)
            os.setuid(uid)

        # wait for SIGHUP to synchronize
        signal.pause()

        if args.prog is not None:
            os.execvp(args.prog, [args.prog])
        else:
            os.execvp(os.environ.get('SHELL'), [os.environ.get('SHELL'), '-i'])

    except:
        import traceback
        import time
        traceback.print_exc()
        time.sleep(10)

if __name__ == '__main__':
    main()
