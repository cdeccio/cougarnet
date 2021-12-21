#!/usr/bin/python3

import argparse
import csv
import io
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

from cougarnet import util


HOST_RE = re.compile(r'^[a-z]([a-z0-9-]*[a-z0-9])?$')
MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')

#TERM="xfce4-terminal"
TERM="lxterminal"
HOSTPREP_MODULE="cougarnet.hostprep"
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

class Host(object):
    def __init__(self, hostname, sock_file, tmux_file, script_file, type='host',
            native_apps=True, terminal=True, prog=None, ipv6=True, routes=None):

        self.hostname = hostname
        self.sock_file = sock_file
        self.tmux_file = tmux_file
        self.script_file = script_file
        self.pid = None
        self.config_file = None
        self.next_int_num = 0
        self.int_to_neighbor = {}
        self.neighbor_to_int = {}
        self.neighbor_by_hostname = {}
        self.int_to_mac = {}
        self.int_to_ip4 = {}
        self.int_to_ip6 = {}
        self.int_to_bw = {}
        self.int_to_delay = {}
        self.int_to_loss = {}
        self.int_to_mtu = {}
        self.int_to_vlan = {}
        self.int_to_trunk = {}
        self.type = type
        self.prog = prog
        self.has_bridge = False
        self.has_vlans = None
        self.hosts_file = None
        self.routes_pre_processed = routes
        self.routes = None

        if not native_apps or str(native_apps).lower() in FALSE_STRINGS:
            self.native_apps = False
        else:
            self.native_apps = True
        if not terminal or str(terminal).lower() in FALSE_STRINGS:
            self.terminal = False
        else:
            self.terminal = True
        if not ipv6 or str(ipv6).lower() in FALSE_STRINGS:
            self.ipv6 = False
        else:
            self.ipv6 = True

        self.create_script_file()

    def __str__(self):
        return self.hostname

    def _get_tmux_server_pid(self):
        if self.tmux_file is None:
            return
        cmd = ['tmux', '-S', self.tmux_file,
                'display-message', '-pF', '#{pid}']
        output = subprocess.run(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE).stdout
        if output:
            return int(output.decode('utf-8').strip())
        else:
            return None

    def process_routes(self):
        self.routes = []

        if self.routes_pre_processed is None:
            return

        routes = self.routes_pre_processed.split(';')
        for route in routes:
            prefix, neighbor, next_hop = route.split('|')
            if not next_hop:
                next_hop = None
            try:
                intf = self.neighbor_to_int[self.neighbor_by_hostname[neighbor]]
            except KeyError:
                raise ValueError(f"The interface connected to {neighbor} " + \
                        f"is designated as a next hop for one of " + \
                        f"{self.hostname}'s routes, but {neighbor} " + \
                        f"is not directly connected to {self.hostname}.")
            self.routes.append((prefix, intf, next_hop))

    def _host_config(self):
        host_info = {
                'hostname': self.hostname,
                'routes': self.routes,
                'native_apps': self.native_apps,
                'type': self.type,
                'ipv6': self.ipv6
                }
        host_info['ip_forwarding'] = self.type == 'router' and self.native_apps
        int_infos = {}
        for intf in self.int_to_neighbor:
            int_infos[intf] = self._int_config(intf)
        host_info['interfaces'] = int_infos
        return host_info

    def _int_config(self, intf):
        return {
                'mac': self.int_to_mac[intf],
                'addrs4': self.int_to_ip4[intf][:],
                'addrs6': self.int_to_ip6[intf][:],
                'bw': self.int_to_bw[intf],
                'delay': self.int_to_delay[intf],
                'loss': self.int_to_loss[intf],
                'mtu': self.int_to_mtu[intf],
                'vlan': self.int_to_vlan[intf],
                'trunk': self.int_to_trunk[intf]
                }

    def create_config(self, config_file):

        host_config = self._host_config()

        self.config_file = config_file
        with open(self.config_file, 'w') as fh:
            fh.write(json.dumps(host_config))

    def create_script_file(self):

        with open(self.script_file, 'w') as fh:
            fh.write('#!/bin/bash\n')
            if self.terminal:
                fh.write(f'exec tmux -S {self.tmux_file} new-session \\; \\\n')
                fh.write(f'    set exit-unattached on \\; \\\n')
                if self.prog is not None:
                    prog = self.prog.replace('|', ' ').replace('"', r'\"')
                    fh.write(f'    send-keys "{prog}" C-m \\; \\\n')
                    fh.write(f'    split-window -v \\;\n')

            else:
                if self.prog is not None:
                    prog = self.prog.replace('|', ' ')
                    fh.write(f'exec {prog}')
                else:
                    fh.write(f'exec bash')

        cmd = ['chmod', '755', self.script_file]
        subprocess.run(cmd, check=True)

    def create_hosts_file(self, other_hosts, hosts_file):
        self.hosts_file = hosts_file

        with open(self.hosts_file, 'w') as write_fh:
            write_fh.write(f'127.0.0.1 localhost {self.hostname}\n')
            with open(other_hosts, 'r') as read_fh:
                write_fh.write(read_fh.read())

    def create_hosts_file_entries(self, fh):
        for intf in self.int_to_neighbor:
            for addr in self.int_to_ip4[intf]:
                slash = addr.find('/')
                if slash >= 0:
                    addr = addr[:slash]
                fh.write(f'{addr} {self.hostname}\n')
            for addr in self.int_to_ip6[intf]:
                slash = addr.find('/')
                if slash >= 0:
                    addr = addr[:slash]
                fh.write(f'{addr} {self.hostname}\n')

    def start(self, commsock_file):
        assert self.config_file is not None, \
                "create_config() must be called before start()"

        cmd = ['sudo', 'touch', f'/run/netns/{self.hostname}']
        subprocess.run(cmd)

        cmd = ['sudo', '-E', 'unshare', '--mount']
        if not (self.type == 'switch' and self.native_apps):
            cmd += [f'--net=/run/netns/{self.hostname}']
        cmd += ['--uts', sys.executable, '-m', f'{HOSTPREP_MODULE}',
                    '--hosts-file', self.hosts_file,
                    '--user', os.environ.get("USER")]

        cmd += ['--prog', self.script_file]
        if not (self.type == 'switch' and self.native_apps):
            cmd += ['--mount-sys']

        cmd += [self.config_file, commsock_file, self.sock_file]

        if self.terminal:
            cmd_quoted = []
            for c in cmd:
                c = c.replace('"', r'\"')
                c = f'"{c}"'
                cmd_quoted.append(c)
            subcmd = ' '.join(cmd_quoted)

            cmd = [TERM, '-t', f'{self.type.capitalize()}: {self.hostname}', '-e', subcmd]

        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def add_int(self, intf, host):
        self.int_to_neighbor[intf] = host
        if host in self.neighbor_to_int:
            raise ValueError('Only one link can exist between two hosts')
        self.neighbor_to_int[host] = intf
        self.neighbor_by_hostname[host.hostname] = host

    def next_int(self):
        int_next = self.next_int_num
        self.next_int_num += 1
        return int_next

    def kill(self):
        if self.pid is not None:
            cmd = ['kill', f'-TERM', str(self.pid)]
            subprocess.run(cmd, stderr=subprocess.DEVNULL)

            if util.pid_is_running(self.pid):
                time.sleep(0.2)
                if util.pid_is_running(self.pid):
                    cmd = ['kill', f'-KILL', str(self.pid)]
                    subprocess.run(cmd, stderr=subprocess.DEVNULL)

        if self.tmux_file is not None:
            tmux_pid = self._get_tmux_server_pid()
            if tmux_pid is not None and \
                    util.pid_is_running(tmux_pid):
                cmd = ['kill', f'-TERM', str(tmux_pid)]
                subprocess.run(cmd, stderr=subprocess.DEVNULL)

                if util.pid_is_running(tmux_pid):
                    time.sleep(0.2)
                    if util.pid_is_running(tmux_pid):
                        cmd = ['kill', f'-KILL', str(tmux_pid)]
                        subprocess.run(cmd, stderr=subprocess.DEVNULL)


    def cleanup(self):
        self.kill()

        #XXX not sure why this while loop is necessary (i.e., why we need to
        #XXX umount several times)
        while True:
            cmd = ['sudo', 'umount', f'/run/netns/{self.hostname}']
            try:
                subprocess.run(cmd, stderr=subprocess.DEVNULL, check=True)
            except subprocess.CalledProcessError:
                break

        if os.path.exists(f'/run/netns/{self.hostname}'):
            cmd = ['sudo', 'rm', f'/run/netns/{self.hostname}']
            subprocess.run(cmd)

        if self.type == 'switch' and self.native_apps:
            cmd = ['sudo', 'ovs-vsctl', 'del-br', self.hostname]
            subprocess.run(cmd)

            for intf in self.int_to_neighbor:
                neighbor = self.int_to_neighbor[intf]
                if neighbor.type == 'switch' and neighbor.native_apps:
                    cmd = ['sudo', 'ip', 'link', 'del', intf]
                    subprocess.run(cmd)

        for f in self.sock_file, self.config_file, self.script_file, \
                self.hosts_file, self.tmux_file:
            if f is not None and os.path.exists(f):
                os.unlink(f)

    def label_for_int(self, intf):
        s = f'<TR><TD COLSPAN="2" ALIGN="left"><B>{intf}:</B></TD></TR>'
        if self.int_to_mac[intf] is not None:
            s += f'<TR><TD ALIGN="right">  </TD><TD>{self.int_to_mac[intf]}</TD></TR>'
        if self.int_to_ip4[intf]:
            s += '<TR><TD ALIGN="RIGHT">  </TD><TD>'
            s += '</TD></TR><TR><TD ALIGN="right">'.join(self.int_to_ip4[intf])
            s += '</TD></TR>'
        if self.int_to_ip6[intf]:
            s += '<TR><TD ALIGN="RIGHT">  </TD><TD>'
            s += '</TD></TR><TR><TD ALIGN="right">'.join(self.int_to_ip6[intf])
            s += '</TD></TR>'
        return s

class VirtualNetwork(object):
    def __init__(self, native_apps, terminal, tmpdir, ipv6):
        self.host_by_name = {}
        self.hostname_by_sock = {}
        self.hosts_file = None
        self.native_apps = native_apps
        self.terminal = terminal
        self.tmpdir = tmpdir
        self.ipv6 = ipv6

        self.comm_dir = os.path.join(self.tmpdir, COMM_DIR)
        self.config_dir = os.path.join(self.tmpdir, CONFIG_DIR)
        self.hosts_dir = os.path.join(self.tmpdir, HOSTS_DIR)
        self.script_dir = os.path.join(self.tmpdir, SCRIPT_DIR)
        self.tmux_dir = os.path.join(self.tmpdir, TMUX_DIR)

        for d in self.comm_dir, self.config_dir, self.hosts_dir, \
                self.script_dir, self.tmux_dir:
            cmd = ['mkdir', '-p', d]
            subprocess.run(cmd, check=True)

    def import_int(self, hostname_addr):
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
                self.import_int(int1_info)
        host2, mac2, addrs42, addrs62, subnet42, subnet62 = \
                self.import_int(int2_info)

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

        self.add_link(host1, host2, **attrs)
        host1.int_to_mac[host1.neighbor_to_int[host2]] = mac1
        host2.int_to_mac[host2.neighbor_to_int[host1]] = mac2
        host1.int_to_ip4[host1.neighbor_to_int[host2]] = addrs41
        host2.int_to_ip4[host2.neighbor_to_int[host1]] = addrs42
        host1.int_to_ip6[host1.neighbor_to_int[host2]] = addrs61
        host2.int_to_ip6[host2.neighbor_to_int[host1]] = addrs62

    def process_routes(self):
        for hostname, host in self.host_by_name.items():
            host.process_routes()

    @classmethod
    def from_file(cls, fh, native_apps, terminal, config_vars, tmpdir, ipv6):
        net = cls(native_apps, terminal, tmpdir, ipv6)
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

        if self.native_apps is not None:
            attrs['native_apps'] = str(self.native_apps)
        if self.terminal is not None:
            attrs['terminal'] = str(self.terminal)
        attrs['ipv6'] = str(self.ipv6)

        self.hostname_by_sock[sock_file] = hostname
        self.host_by_name[hostname] = \
                Host(hostname, sock_file, tmux_file, script_file, **attrs)

    def add_link(self, host1, host2, bw=None, delay=None, loss=None,
            mtu=None, vlan=None, trunk=None):
        if isinstance(host1, str):
            host1 = self.host_by_name[host1]
        if isinstance(host2, str):
            host2 = self.host_by_name[host2]

        num1 = host1.next_int()
        num2 = host2.next_int()
        int1 = f'{host1.hostname}-{host2.hostname}'
        int2 = f'{host2.hostname}-{host1.hostname}'
        host1.add_int(int1, host2)
        host2.add_int(int2, host1)
        host1.int_to_bw[int1] = bw
        host2.int_to_bw[int2] = bw
        host1.int_to_delay[int1] = delay
        host2.int_to_delay[int2] = delay
        host1.int_to_loss[int1] = loss
        host2.int_to_loss[int2] = loss
        host1.int_to_mtu[int1] = mtu
        host2.int_to_mtu[int2] = mtu
        if host1.type == 'switch':
            host1.int_to_vlan[int1] = vlan
        else:
            host1.int_to_vlan[int1] = None
        if host2.type == 'switch':
            host2.int_to_vlan[int2] = vlan
        else:
            host2.int_to_vlan[int2] = None
        if host1.type == 'switch' and host2.type == 'switch':
            if not trunk or str(trunk).lower() in FALSE_STRINGS:
                host1.int_to_trunk[int1] = False
                host2.int_to_trunk[int2] = False
            else:
                host1.int_to_trunk[int1] = True
                host2.int_to_trunk[int2] = True
        else:
            host1.int_to_trunk[int1] = None
            host2.int_to_trunk[int2] = None

    def apply_links(self):
        done = set()
        for hostname, host in self.host_by_name.items():
            for intf, neighbor in host.int_to_neighbor.items():
                host1 = host
                host2 = neighbor
                int1 = intf
                int2 = host2.neighbor_to_int[host]
                if (host1, host2, int1, int2) in done:
                    continue
                done.add((host1, host2, int1, int2))
                done.add((host2, host1, int2, int1))

                # Sanity check
                if host1.type == 'switch':
                    has_vlans = bool(host1.int_to_vlan[int1] is not None or \
                            host1.int_to_trunk[int1])
                    if has_vlans and host1.has_vlans is False or \
                            not has_vlans and host1.has_vlans:
                        raise InconsistentConfiguration(
                                f'Some links on {host1.hostname} have ' + \
                                        'VLANs while others do not!')
                    host1.has_vlans = has_vlans
                if host2.type == 'switch':
                    has_vlans = bool(host2.int_to_vlan[int2] is not None or \
                            host2.int_to_trunk[int2])
                    if has_vlans and host2.has_vlans is False or \
                            not has_vlans and host2.has_vlans:
                        raise InconsistentConfiguration(
                                f'Some links on {host2.hostname} have ' + \
                                        'VLANs while others do not!')
                    host2.has_vlans = has_vlans

                # create both interfaces
                cmd = ['sudo', 'ip', 'link', 'add', int1,
                        'type', 'veth', 'peer', 'name', int2]
                subprocess.run(cmd, check=True)

                host1_bridge = False
                if host1.type == 'switch' and host1.native_apps:
                    host1_bridge = True
                    if not host1.has_bridge:
                        cmd = ['sudo', 'ovs-vsctl', 'add-br',
                                host1.hostname]
                        subprocess.run(cmd, check=True)
                        host1.has_bridge = True

                    cmd = ['sudo', 'ovs-vsctl', 'add-port',
                            host1.hostname, int1]
                    if host1.type == 'switch':
                        if host1.int_to_vlan[int1] is not None:
                            cmd.append(f'tag={host1.int_to_vlan[int1]}')
                        elif host1.int_to_trunk[int1]:
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
                            host2.hostname, int2]
                    if host2.type == 'switch':
                        if host2.int_to_vlan[int2] is not None:
                            cmd.append(f'tag={host2.int_to_vlan[int2]}')
                        elif host2.int_to_trunk[int2]:
                            pass
                        else:
                            cmd.append('tag=0')
                    subprocess.run(cmd, check=True)

                # Move interfaces to their appropriate namespaces
                if host1_bridge:
                    cmd = ['sudo', 'ip', 'link', 'set', int1, 'up']
                    subprocess.run(cmd, check=True)
                else:
                    cmd = ['sudo', 'ip', 'link', 'set', int1, 'netns',
                            host1.hostname]
                    subprocess.run(cmd, check=True)
                if host2_bridge:
                    cmd = ['sudo', 'ip', 'link', 'set', int2, 'up']
                    subprocess.run(cmd, check=True)
                else:
                    cmd = ['sudo', 'ip', 'link', 'set', int2, 'netns',
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

    def start(self, wireshark_host=None, wireshark_interfaces=None):
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
        if wireshark_host is not None:
            self.start_wireshark(self.host_by_name[wireshark_host], interfaces=wireshark_interfaces)

        # let hosts know that they can start now
        for hostname, host in self.host_by_name.items():
            self.commsock.sendto(b'\x00', host.sock_file)

    def cleanup(self):
        for hostname, host in self.host_by_name.items():
            host.cleanup()

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
            for intf, neighbor in host.int_to_neighbor.items():
                host1 = host
                host2 = neighbor
                int1 = intf
                int2 = host2.neighbor_to_int[host]
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
            for intf, neighbor in host.int_to_neighbor.items():
                host1 = host
                host2 = neighbor
                int1 = intf
                int2 = host2.neighbor_to_int[host]
                if (host1, host2, int1, int2) in done:
                    continue
                done.add((host1, host2, int1, int2))
                done.add((host2, host1, int2, int1))
                G.add_edge(host1.hostname, host2.hostname)
        img = G.draw(prog='dot')
        subprocess.run(['graph-easy', '--from', 'graphviz'], input=img,
                stderr=subprocess.DEVNULL)

    def start_wireshark(self, host, interfaces=None):
        if host.type == 'switch' and host.native_apps:
            cmd = ['sudo', 'wireshark']
        else:
            sys.stderr.write('Sorry, at the moment wireshark can only be run on switches using "native app".\n')
            return
            cmd = ['sudo', '-E', 'ip', 'netns', 'exec', host.hostname, 'wireshark']
        if interfaces is not None and type(interfaces) is list and len(interfaces):
            for interface in interfaces:
                cmd += ['-i', interface]
            cmd += ['-k']
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
            metavar='NODE',
            help='Start wireshark for the specified node')
    parser.add_argument('--wireshark-interfaces',
            type=str, nargs="+",
            metavar='INTERFACE',
            help='Start wireshark capturing on the specified interface(s)')
    parser.add_argument('--display',
            action='store_const', const=True, default=False,
            help='Display the network configuration as text')
    parser.add_argument('--vars',
            action='store', type=str, default=None,
            help='Variables to be replaced in the configuration file (name=value[,name=value...])')
    parser.add_argument('--terminal',
            action='store', type=str, choices=('all', 'none'), default=None,
            help='Specify that all virtual hosts should launch (all) or not launch (none) a terminal.')
    parser.add_argument('--disable-ipv6',
            action='store_const', const=True, default=False,
            help='Disable IPv6')
    parser.add_argument('--native-apps',
            action='store', type=str, choices=('all', 'none'), default=None,
            help='Specify that all virtual hosts should enable (all) or disable (none) native apps.')
    parser.add_argument('--display-file',
            type=argparse.FileType('wb'), action='store',
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

    if args.native_apps == 'all':
        native_apps = True
    elif args.native_apps == 'none':
        native_apps = False
    else:
        native_apps = None

    if args.terminal == 'all':
        terminal = True
    elif args.terminal == 'none':
        terminal = False
    else:
        terminal = None

    if args.vars:
        config_vars = dict([p.split('=', maxsplit=1) \
                for p in args.vars.split(',')])
    else:
        config_vars = {}

    ipv6 = not args.disable_ipv6

    net = VirtualNetwork.from_file(args.config_file, native_apps, \
            terminal, config_vars, tmpdir.name, ipv6)

    if args.wireshark is not None and \
            args.wireshark not in net.host_by_name:
        sys.stderr.write(f'The host specified for wireshark with the ' + \
                f'--wireshark/-w option ({args.wireshark}) does not exist.\n')
        sys.exit(1)

    if args.display:
        net.display_to_screen()
    if args.display_file:
        net.display_to_file(args.display_file)

    try:
        net.config()
        if args.wireshark_interfaces and len(args.wireshark_interfaces):
            net.start(args.wireshark, wireshark_interfaces=args.wireshark_interfaces)
        else:
            net.start(args.wireshark)
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
