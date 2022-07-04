#!/usr/bin/python3

import argparse
import csv
import io
import ipaddress
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

from cougarnet import util
from .host import HostConfig


HOST_RE = re.compile(r'^[a-z]([a-z0-9-]*[a-z0-9])?$')
MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')

TMPDIR=os.path.join(os.environ.get('HOME', '.'), 'cougarnet-tmp')
MAIN_FILENAME='_main'
COMM_DIR='comm'
CONFIG_DIR='config'
HOSTS_DIR='hosts'
SCRIPT_DIR='scripts'
TMUX_DIR='tmux'
SCRIPT_EXTENSION='sh'

FALSE_STRINGS = ('off', 'no', 'n', 'false', 'f', '0')

class HostNotStarted(Exception):
    pass

class InconsistentConfiguration(Exception):
    pass

class VirtualNetwork(object):
    def __init__(self, terminal_hosts, tmpdir, ipv6):
        self.host_by_name = {}
        self.hostname_by_sock = {}
        self.hosts_file = None
        self.terminal_hosts = terminal_hosts
        self.tmpdir = tmpdir
        self.ipv6 = ipv6

        self.bridge_interfaces = set()

        self.comm_dir = os.path.join(self.tmpdir, COMM_DIR)
        self.config_dir = os.path.join(self.tmpdir, CONFIG_DIR)
        self.hosts_dir = os.path.join(self.tmpdir, HOSTS_DIR)
        self.script_dir = os.path.join(self.tmpdir, SCRIPT_DIR)
        self.tmux_dir = os.path.join(self.tmpdir, TMUX_DIR)

        for d in self.comm_dir, self.config_dir, self.hosts_dir, \
                self.script_dir, self.tmux_dir:
            cmd = ['mkdir', '-p', d]
            subprocess.run(cmd, check=True)

    def parse_int(self, hostname_addr):
        parts = hostname_addr.split(',')
        hostname = parts[0]
        mac = None
        addrs = parts[1:]
        addrs4 = []
        addrs6 = []
        subnet4 = None
        subnet6 = None
        for addr in addrs:

            # MAC address
            m = MAC_RE.search(addr)
            if m is not None:
                if mac is not None:
                    raise ValueError(f'Only one MAC address is allowed')
                mac = addr
                continue

            # IP address
            slash = addr.find('/')
            if slash < 0:
                raise ValueError(f'Address for {hostname} interface ' + \
                        'must include prefix length!')
            if ':' in addr:
                # IPv6 address
                subnet = str(ipaddress.IPv6Network(addr, strict=False))
                if subnet6 is None:
                    subnet6 = subnet
                if subnet6 != subnet:
                    raise ValueError(f'All connected IP addresses ' + \
                            'must be on the same subnet!')
                addrs6.append(addr)
            else:
                # IPv4 address
                subnet = str(ipaddress.IPv4Network(addr, strict=False))
                if subnet4 is None:
                    subnet4 = subnet
                if subnet4 != subnet:
                    raise ValueError(f'All connected IP addresses ' + \
                            'must be on the same subnet!')
                addrs4.append(addr)

        if hostname not in self.host_by_name:
            raise ValueError(f'Host not defined: {hostname}')
        host = self.host_by_name[hostname]
        return host, mac, addrs4, addrs6, subnet4, subnet6

    def import_link(self, line):
        parts = line.split(maxsplit=2)
        if len(parts) < 2 or len(parts) > 3:
            raise ValueError(f'Invalid link format.')

        int1_info, int2_info = parts[:2]
        host1, mac1, addrs41, addrs61, subnet41, subnet61 = \
                self.parse_int(int1_info)
        host2, mac2, addrs42, addrs62, subnet42, subnet62 = \
                self.parse_int(int2_info)

        if set(addrs41).intersection(set(addrs42)):
            raise ValueError(f'Addresses for {host1.hostname} and ' + \
                    f'{host2.hostname} cannot be the same!')
        if subnet41 is not None and subnet42 is not None and \
                subnet41 != subnet42:
            raise ValueError(f'Addresses for {host1.hostname} and ' + \
                    f'{host2.hostname} must be in the same subnet!')
        if set(addrs61).intersection(set(addrs62)):
            raise ValueError(f'Addresses for {host1.hostname} and ' + \
                    f'{host2.hostname} cannot be the same!')
        if subnet61 is not None and subnet62 is not None and \
                subnet61 != subnet62:
            raise ValueError(f'Addresses for {host1.hostname} and ' + \
                    f'{host2.hostname} must be in the same subnet!')

        if len(parts) > 2:
            s = io.StringIO(parts[2])
            csv_reader = csv.reader(s)
            attrs = dict([p.split('=', maxsplit=1) \
                    for p in next(csv_reader)])
        else:
            attrs = {}

        int1, int2 = self.add_link(host1, host2, **attrs)
        int1.update(mac_addr=mac1, ipv4_addrs=addrs41, ipv6_addrs=addrs61)
        int2.update(mac_addr=mac2, ipv4_addrs=addrs42, ipv6_addrs=addrs62)

    def process_routes(self):
        for hostname, host in self.host_by_name.items():
            host.process_routes()

    @classmethod
    def from_file(cls, fh, terminal_hosts, config_vars, tmpdir, ipv6):
        net = cls(terminal_hosts, tmpdir, ipv6)
        mode = None
        for line in fh:
            line = line.strip()

            for name, val in config_vars.items():
                var_re = re.compile(fr'\${name}(\W|$)')
                line = var_re.sub(fr'{val}\1', line)

            if line == 'NODES':
                mode = 'node'
                continue
            elif line == 'LINKS':
                mode = 'link'
                continue
            elif not line:
                continue
            elif line.startswith('#'):
                continue

            if mode == 'node':
                net.import_node(line)
            elif mode == 'link':
                net.import_link(line)
            else:
                pass

        net.process_routes()

        return net

    def is_valid_hostname(self, hostname):
        if not hostname[0].isalpha():
            return False
        if HOST_RE.search(hostname) is None:
            return False
        return True

    def import_node(self, line):
        parts = line.split()
        if len(parts) < 1 or len(parts) > 2:
            raise ValueError(f'Invalid node format: {line}')

        hostname = parts[0]
        if not self.is_valid_hostname(hostname):
            raise ValueError(f'Invalid hostname: {hostname}')
        if hostname == MAIN_FILENAME:
            raise ValueError(f'Hostname cannot be {hostname}')

        sock_file = os.path.join(self.comm_dir, hostname)
        script_file = os.path.join(self.script_dir, f'{hostname}.sh')
        tmux_file = os.path.join(self.tmux_dir, hostname)
        if len(parts) > 1:
            s = io.StringIO(parts[1])
            csv_reader = csv.reader(s)
            attrs = dict([p.split('=', maxsplit=1) \
                    for p in next(csv_reader)])
        else:
            attrs = {}

        if self.terminal_hosts:
            if hostname in self.terminal_hosts or 'all' in self.terminal_hosts:
                attrs['terminal'] = 'true'
            else:
                attrs['terminal'] = 'false'
        attrs['ipv6'] = str(self.ipv6)

        self.hostname_by_sock[sock_file] = hostname
        self.host_by_name[hostname] = \
                HostConfig(hostname, sock_file, tmux_file, script_file, **attrs)

    def add_link(self, host1, host2, bw=None, delay=None, loss=None,
            mtu=None, vlan=None, trunk=None):
        if isinstance(host1, str):
            host1 = self.host_by_name[host1]
        if isinstance(host2, str):
            host2 = self.host_by_name[host2]

        #XXX deprecated
        num1 = host1.next_int()
        num2 = host2.next_int()

        int1_name = f'{host1.hostname}-{host2.hostname}'
        int2_name = f'{host2.hostname}-{host1.hostname}'

        vlan1 = None
        vlan2 = None
        trunk1 = None
        trunk2 = None

        if host1.type == 'switch':
            vlan1 = vlan
        else:
            vlan1 = None
        if host2.type == 'switch':
            vlan2 = vlan
        else:
            vlan2 = None

        if host1.type == 'switch' and host2.type == 'switch':
            if not trunk or str(trunk).lower() in FALSE_STRINGS:
                trunk1 = False
                trunk2 = False
            else:
                trunk1 = True
                trunk2 = True
        else:
            trunk1 = None
            trunk2 = None

        intf1 = host1.add_int(int1_name, host2,
                        bw=bw, delay=delay, loss=loss, mtu=mtu,
                        vlan=vlan1, trunk=trunk1)
        intf2 = host2.add_int(int2_name, host1,
                        bw=bw, delay=delay, loss=loss, mtu=mtu,
                        vlan=vlan2, trunk=trunk2)

        return intf1, intf2

    def apply_links(self):
        done = set()
        for hostname, host in self.host_by_name.items():
            for intf, neighbor in host.neighbor_by_int.items():
                host1 = host
                host2 = neighbor
                int1 = intf
                int2 = host2.int_by_neighbor[host]
                if (host1, host2, int1, int2) in done:
                    continue
                done.add((host1, host2, int1, int2))
                done.add((host2, host1, int2, int1))

                # Sanity check
                if host1.type == 'switch':
                    has_vlans = bool(int1.vlan is not None or int1.trunk)
                    if has_vlans and host1.has_vlans is False or \
                            not has_vlans and host1.has_vlans:
                        raise InconsistentConfiguration(
                                f'Some links on {host1.hostname} have ' + \
                                        'VLANs while others do not!')
                    host1.has_vlans = has_vlans
                if host2.type == 'switch':
                    has_vlans = bool(int2.vlan is not None or int2.trunk)
                    if has_vlans and host2.has_vlans is False or \
                            not has_vlans and host2.has_vlans:
                        raise InconsistentConfiguration(
                                f'Some links on {host2.hostname} have ' + \
                                        'VLANs while others do not!')
                    host2.has_vlans = has_vlans

                # For each interface, we create both the interface itself and a
                # "ghost" interface that will be on the host.
                ghost1 = f'{int1.name}-ghost'
                ghost2 = f'{int2.name}-ghost'
                cmd = ['sudo', 'ip', 'link', 'add', int1.name,
                        'type', 'veth', 'peer', 'name', ghost1]
                subprocess.run(cmd, check=True)
                cmd = ['sudo', 'ip', 'link', 'add', int2.name,
                        'type', 'veth', 'peer', 'name', ghost2]
                subprocess.run(cmd, check=True)

                # We now connect to the two ghost interfaces together with a
                # bridge.
                br = f'{int1.name}-br'
                cmd = ['sudo', 'ip', 'link', 'add', br, 'type', 'bridge',
                        'stp_state', '0', 'vlan_filtering', '0']
                subprocess.run(cmd, check=True)
                cmd = ['sudo', 'ip', 'link', 'set', ghost1, 'master', br]
                subprocess.run(cmd, check=True)
                cmd = ['sudo', 'ip', 'link', 'set', ghost2, 'master', br]
                subprocess.run(cmd, check=True)
                cmd = ['sudo', 'ip', 'link', 'set', ghost1, 'up']
                subprocess.run(cmd, check=True)
                cmd = ['sudo', 'ip', 'link', 'set', ghost2, 'up']
                subprocess.run(cmd, check=True)
                cmd = ['sudo', 'ip', 'link', 'set', br, 'up']
                subprocess.run(cmd, check=True)
                self.bridge_interfaces.add(br)

                # These interfaces should have *no* addresses, including IPv6
                cmd = ['sudo', 'sysctl', f'net.ipv6.conf.{ghost1}.disable_ipv6=1']
                subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)
                cmd = ['sudo', 'sysctl', f'net.ipv6.conf.{ghost2}.disable_ipv6=1']
                subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)
                cmd = ['sudo', 'sysctl', f'net.ipv6.conf.{br}.disable_ipv6=1']
                subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)

                host1_bridge = False
                if host1.type == 'switch' and host1.native_apps:
                    host1_bridge = True
                    if not host1.has_bridge:
                        cmd = ['sudo', 'ovs-vsctl', 'add-br',
                                host1.hostname]
                        subprocess.run(cmd, check=True)
                        host1.has_bridge = True

                    cmd = ['sudo', 'ovs-vsctl', 'add-port',
                            host1.hostname, int1.name]
                    if host1.type == 'switch':
                        if int1.vlan is not None:
                            cmd.append(f'tag={int1.vlan}')
                        elif int1.trunk:
                            pass
                        else:
                            cmd.append('tag=0')
                    subprocess.run(cmd, check=True)

                host2_bridge = False
                if host2.type == 'switch' and host2.native_apps:
                    host2_bridge = True
                    if not host2.has_bridge:
                        cmd = ['sudo', 'ovs-vsctl', 'add-br',
                                host2.hostname]
                        subprocess.run(cmd, check=True)
                        host2.has_bridge = True

                    cmd = ['sudo', 'ovs-vsctl', 'add-port',
                            host2.hostname, int2.name]
                    if host2.type == 'switch':
                        if int2.vlan is not None:
                            cmd.append(f'tag={int2.vlan}')
                        elif int2.trunk:
                            pass
                        else:
                            cmd.append('tag=0')
                    subprocess.run(cmd, check=True)

                # Move interfaces to their appropriate namespaces
                if host1_bridge:
                    cmd = ['sudo', 'ip', 'link', 'set', int1.name, 'up']
                    subprocess.run(cmd, check=True)
                else:
                    cmd = ['sudo', 'ip', 'link', 'set', int1.name, 'netns',
                            host1.hostname]
                    subprocess.run(cmd, check=True)
                if host2_bridge:
                    cmd = ['sudo', 'ip', 'link', 'set', int2.name, 'up']
                    subprocess.run(cmd, check=True)
                else:
                    cmd = ['sudo', 'ip', 'link', 'set', int2.name, 'netns',
                            host2.hostname]
                    subprocess.run(cmd, check=True)

    def create_hosts_file(self):
        self.hosts_file = os.path.join(self.hosts_dir, MAIN_FILENAME)

        with open(self.hosts_file, 'w') as fh:
            for hostname, host in self.host_by_name.items():
                host.create_hosts_file_entries(fh)

    def config(self):
        self.commsock_file = os.path.join(self.comm_dir, MAIN_FILENAME)
        self.commsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        self.commsock.bind(self.commsock_file)

        self.create_hosts_file()
        for hostname, host in self.host_by_name.items():
            config_file = os.path.join(self.config_dir, f'{hostname}.cfg')
            hosts_file = os.path.join(self.hosts_dir, hostname)
            host.create_config(config_file)
            host.create_hosts_file(self.hosts_file, hosts_file)

    def wait_for_phase1_startup(self, host):
        # set to non-bocking with timeout 3
        self.commsock.settimeout(3)
        try:
            data, peer = self.commsock.recvfrom(16)
            if peer != host.sock_file:
                raise Exception('Received packet from someone else!')
            host.pid = int(data.decode('utf-8'))
        except socket.timeout:
            raise HostNotStarted(f'{host.hostname} did not start properly.')
        finally:
            # revert to non-blocking
            self.commsock.settimeout(None)

    def wait_for_phase2_startup(self):
        # set to non-bocking with timeout 3
        self.commsock.settimeout(3)
        try:
            sock_files = set([host.sock_file \
                    for hostname, host in self.host_by_name.items()])
            start_time = time.time()
            end_time = start_time + 3
            while sock_files and time.time() < end_time:
                data, peer = self.commsock.recvfrom(1)
                if peer in sock_files:
                    sock_files.remove(peer)
        except socket.timeout:
            pass
        finally:
            # revert to blocking
            self.commsock.settimeout(None)

        if not sock_files:
            # we're done!
            return

        # if there were some sock_files left over, map the file to its host,
        # and raise an error
        sock_file_to_hostname = {}
        for hostname, host in self.host_by_name.items():
            sock_file_to_hostname[host.sock_file] = hostname

        for sock_file in sock_files:
            hostname = sock_file_to_hostname[sock_file]
            host = self.host_by_name[hostname]
            cmd = ['ps', '-p', str(host.pid)]
            p = subprocess.run(cmd, stdout=subprocess.DEVNULL)
            if p.returncode != 0:
                raise HostNotStarted(f'{hostname} did not start properly.')
            else:
                raise HostNotStarted(f'{hostname} is taking too long.')

    def start(self, wireshark_ints):
        # start the hosts and wait for each to write its PID to the
        for hostname, host in self.host_by_name.items():
            host.start(self.commsock_file)
            self.wait_for_phase1_startup(host)

        # we have to wait to apply the links until the namespace is created
        # i.e., process has to start, as evidenced by pid file
        self.apply_links()

        # let hosts know that virtual interfaces have been
        # created, so they can proceed with network configuration
        for hostname, host in self.host_by_name.items():
            self.commsock.sendto(b'\x00', host.sock_file)

        self.wait_for_phase2_startup()
        if wireshark_ints:
            self.start_wireshark(wireshark_ints)

        # let hosts know that they can start now
        for hostname, host in self.host_by_name.items():
            self.commsock.sendto(b'\x00', host.sock_file)

    def cleanup(self):
        for hostname, host in self.host_by_name.items():
            host.cleanup()

        for intf in self.bridge_interfaces:
            cmd = ['sudo', 'ip', 'link', 'del', intf]
            subprocess.run(cmd)

        os.unlink(self.hosts_file)

        self.commsock.close()
        os.unlink(self.commsock_file)

        for d in self.comm_dir, self.config_dir, self.hosts_dir, \
                self.script_dir, self.tmux_dir:
            os.rmdir(d)

    def label_for_link(self, host1, int1, host2, int2):
        s = '<<TABLE BORDER="0">' + host1.label_for_int(int1) + \
                '<TR><TD COLSPAN="2"></TD></TR>' + \
                host2.label_for_int(int2) + \
                '</TABLE>>'
        return s

    def display_to_file(self, output_file):
        from pygraphviz import AGraph
        G = AGraph()

        done = set()
        for hostname, host in self.host_by_name.items():
            for intf, neighbor in host.neighbor_by_int.items():
                host1 = host
                host2 = neighbor
                int1 = intf
                int2 = host2.int_by_neighbor[host]
                if (host1, host2, int1, int2) in done:
                    continue
                done.add((host1, host2, int1, int2))
                done.add((host2, host1, int2, int1))
                G.add_edge(host1.hostname, host2.hostname,
                        label=self.label_for_link(host1, int1, host2, int2))
        img = G.draw(prog='dot')
        G.draw(output_file, format='png', prog='dot')

    def display_to_screen(self):
        from pygraphviz import AGraph
        G = AGraph()

        done = set()
        for hostname, host in self.host_by_name.items():
            for intf, neighbor in host.neighbor_by_int.items():
                host1 = host
                host2 = neighbor
                int1 = intf
                int2 = host2.int_by_neighbor[host]
                if (host1, host2, int1, int2) in done:
                    continue
                done.add((host1, host2, int1, int2))
                done.add((host2, host1, int2, int1))
                G.add_edge(host1.hostname, host2.hostname)
        img = G.draw(prog='dot')
        subprocess.run(['graph-easy', '--from', 'graphviz'], input=img,
                stderr=subprocess.DEVNULL)

    def start_wireshark(self, ints):
        cmd = ['wireshark']
        for intf in ints:
            cmd += ['-i', intf]
        if ints:
            cmd.append('-k')
        subprocess.Popen(cmd)

    def message_loop(self):
        start_time = time.time()
        while True:
            data, peer = self.commsock.recvfrom(4096)
            msg = data.decode('utf-8')
            if peer is not None:
                hostname = self.hostname_by_sock[peer]
            else:
                hostname = '??'
            ts = time.time() - start_time
            print('%000.3f \033[1m%4s\033[0m  %s' % (ts, hostname, msg))

def check_requirements(args):

    if os.geteuid() == 0:
        sys.stderr.write(f'Please run this program as a non-privileged user.\n')
        sys.exit(1)

    try:
        subprocess.run(['sudo', '-k'], check=True)
        subprocess.run(['sudo', '-n', '-v'], check=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f'Please run visudo to allow your user to run ' + \
                'sudo without a password, using the NOPASSWD option.\n')
        sys.exit(1)

    # make sure working directories exist
    cmd = ['sudo', 'mkdir', '-p', '/run/netns']
    subprocess.run(cmd, check=True)
    cmd = ['mkdir', '-p', TMPDIR]
    subprocess.run(cmd, check=True)

    if args.display or args.display_file:
        try:
            from pygraphviz import AGraph
        except ImportError:
            sys.stderr.write('Pygraphviz is required for the --display and ' + \
                    '--display-file options\n')
            sys.exit(1)

        if args.display:
            try:
                subprocess.run(['graph-easy', '--help'], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, check=True)
            except subprocess.CalledProcessError:
                pass
            except OSError as e:
                sys.stderr.write('graph-easy is required with the ' + \
                        f'--display: {str(e)}.\n')
                sys.exit(1)


    if args.wireshark is not None:
        try:
            subprocess.run(['wireshark', '-h'], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, check=True)
        except OSError as e:
            sys.stderr.write('wireshark is required with the ' + \
                    f'--wireshark/-w option: {str(e)}.\n')
            sys.exit(1)

    try:
        subprocess.run(['sudo', 'ovs-vsctl', '-V'], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f'Open vSwitch is required: {str(e)}\n')
        sys.exit(1)

def warn_on_sigttin(sig, frame):
    sys.stderr.write('Warning: SIGTTIN received\n')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wireshark', '-w',
            action='store', type=str, default=None,
            metavar='LINKS',
            help='Start wireshark for the specified links (host1-host2[,host2-host3,...])')
    parser.add_argument('--display',
            action='store_const', const=True, default=False,
            help='Display the network configuration as text')
    parser.add_argument('--vars',
            action='store', type=str, default=None,
            help='Specify variables to be replaced in the configuration file (name=value[,name=value,...])')
    parser.add_argument('--terminal',
            action='store', type=str, default=None,
            metavar='HOSTNAMES',
            help='Specify which virtual hosts should launch a terminal (all|none|host1[,host2,...])')
    parser.add_argument('--disable-ipv6',
            action='store_const', const=True, default=False,
            help='Disable IPv6')
    parser.add_argument('--display-file',
            type=argparse.FileType('wb'), action='store',
            metavar='FILE',
            help='Print the network configuration to a file (.png)')
    parser.add_argument('config_file',
            type=argparse.FileType('r'), action='store',
            help='File containing the network configuration')
    args = parser.parse_args(sys.argv[1:])

    check_requirements(args)

    signal.signal(21, warn_on_sigttin)

    try:
        tmpdir = tempfile.TemporaryDirectory(dir=TMPDIR)
    except PermissionError:
        sys.stderr.write(f'Unable to create working directory.  Check permissions of {TMPDIR}.\n')
        sys.exit(1)

    if args.terminal is None:
        terminal_hosts = []
    else:
        terminal_hosts = args.terminal.split(',')

    if args.vars:
        config_vars = dict([p.split('=', maxsplit=1) \
                for p in args.vars.split(',')])
    else:
        config_vars = {}

    ipv6 = not args.disable_ipv6

    net = VirtualNetwork.from_file(args.config_file, \
            terminal_hosts, config_vars, tmpdir.name, ipv6)

    wireshark_ints = []
    if args.wireshark is not None:
        wireshark_ints = args.wireshark.split(',')
        for intf in wireshark_ints:
            intf = intf.strip()
            try:
                host1, host2 = intf.split('-')
            except ValueError:
                sys.stderr.write(f'Invalid link passed to the ' + \
                        f'--wireshark/-w option: {intf}\n')
                sys.exit(1)
            if host1 not in net.host_by_name:
                sys.stderr.write(f'Invalid link passed to the ' + \
                        f'--wireshark/-w option; host does not exist: {host1}\n')
                sys.exit(1)
            if host2 not in net.host_by_name:
                sys.stderr.write(f'Invalid link passed to the ' + \
                        f'--wireshark/-w option; host does not exist: {host2}\n')
                sys.exit(1)
            if host2 not in net.host_by_name[host1].neighbor_by_hostname:
                sys.stderr.write(f'Invalid link passed to the ' + \
                        f'--wireshark/-w option; link does not exist: {intf}\n')
                sys.exit(1)
        wireshark_ints = [f'{intf}-ghost' for intf in wireshark_ints]

    if args.display:
        net.display_to_screen()
    if args.display_file:
        net.display_to_file(args.display_file)

    try:
        net.config()
        net.start(wireshark_ints)
        sys.stdout.write('Ctrl-c to quit\n')
        net.message_loop()
    except KeyboardInterrupt:
        pass
    finally:
        # sometimes ctrl-c gets sent twice, interrupting with SIGINT a second
        # time, and cleanup does not happen.  So here we tell the code to
        # ignore SIGINT, so cleanup can finish.  If you really want to kill it,
        # then use SIGTERM or (gasp!) SIGKILL.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        net.cleanup()

if __name__ == '__main__':
    main()
