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

FALSE_STRINGS = ('off', 'no', 'n', 'false', 'f', '0')

class VirtualHost:
    def __init__(self, config_fh):
        self.ints = None
        self.hostname = None
        self.type = None
        self.gw4 = None
        self.gw6 = None

        self._apply_config(config_fh)

    def _apply_config(self, fh):
        line = fh.readline().strip()
        parts = line.split()
        if len(parts) < 1 or len(parts) > 2:
            raise ValueError(f'Invalid node format: {line}')

        self.hostname = parts[0]
        cmd = ['hostname', self.hostname]
        subprocess.run(cmd, check=True)

        if len(parts) > 1:
            attrs = dict([p.split('=', maxsplit=1) \
                            for p in parts[1].split(',')])
        else:
            attrs = {}

        arp = False
        iptables = True
        for name, val in attrs.items():
            if name == 'gw4':
                # set gateway
                pass
            elif name == 'gw6':
                # set gateway
                pass
            elif name == 'arp':
                if not val or val.lower() in FALSE_STRINGS:
                    arp = False
                else:
                    arp = True
            elif name == 'iptables':
                if not val or val.lower() in FALSE_STRINGS:
                    iptables = False
                else:
                    iptables = True
        self.ints = []
        for line in fh.readlines():
            line = line.strip()
            parts = line.split(',')
            intf = parts[0]
            addrs = parts[2:]

            self.ints.append(intf)

            if len(parts) > 1:
                mac = parts[1]
                # set MAC address, if specified
                if mac:
                    cmd = ['ip', 'link', 'set', intf, 'address', mac]
                    subprocess.run(cmd, check=True)

            # bring link up
            cmd = ['ip', 'link', 'set', intf, 'up']
            subprocess.run(cmd, check=True)

            if not arp:
                # disable ARP
                cmd = ['ip', 'link', 'set', intf, 'arp', 'off']
                subprocess.run(cmd, check=True)

            # enable iptables
            if iptables:
                cmd = ['iptables', '-t', 'filter', '-I', 'INPUT', '-j', 'DROP']
                subprocess.run(cmd, check=True)
                cmd = ['ip6tables', '-t', 'filter', '-I', 'INPUT', '-j', 'DROP']
                subprocess.run(cmd, check=True)

            # add each IP address
            for addr in addrs:
                cmd = ['ip', 'addr', 'add', addr, 'dev', intf]
                subprocess.run(cmd, check=True)

            # disable router solicitations
            cmd = ['sysctl', f'net.ipv6.conf.{intf}.router_solicitations=0']
            subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)

def user_group_info(user):
    pwinfo = pwd.getpwnam(user)
    uid = pwinfo.pw_uid

    groups = [pwinfo.pw_gid]
    for gr in grp.getgrall():
        if user in gr.gr_mem:
            groups.append(gr.gr_gid)

    return uid, groups

def sighup_handler(signum, frame):
    pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hosts-file', '-f',
            action='store', type=str, default=None,
            help='Specify the hosts file')
    parser.add_argument('--comm-sock', '-s',
            action='store', type=str, default=None,
            help='Path to UNIX socket with which we communicate with the' + \
                    'coordinating process')
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

        if args.comm_sock:
            os.environ['COUGARNET_COMM_SOCK'] = args.comm_sock

        host = VirtualHost(args.config_file)

        cmd = ['mount', '-t', 'sysfs', '/sys', '/sys']
        subprocess.run(cmd, check=True)

        if args.hosts_file is not None:
            cmd = ['mount', '-o', 'bind', args.hosts_file, '/etc/hosts']
            subprocess.run(cmd, check=True)

        if args.user is not None:
            uid, groups = user_group_info(args.user)

        cmd = ['rm', args.pid_file.name]
        subprocess.run(cmd, check=True)

        if args.user is not None:
            os.setgroups(groups)
            os.setuid(uid)

        # wait for SIGHUP to synchronize
        signal.pause()

        if args.prog is not None:
            prog_args = args.prog.split('|')
            os.execvp(args.prog, [prog_args])
        else:
            os.execvp(os.environ.get('SHELL'), [os.environ.get('SHELL'), '-i'])

    except:
        import traceback
        import time
        traceback.print_exc()
        time.sleep(10)

if __name__ == '__main__':
    main()
