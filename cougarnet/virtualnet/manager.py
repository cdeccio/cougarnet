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
Classes and main function related to reading the configuration for a virtual
network and starting it.
'''

import argparse
import csv
import io
import ipaddress
import json
import logging
import os
import pickle
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

from cougarnet.errors import ConfigurationError, StartupError, SysCmdError
from cougarnet import util

from .cmd import run_cmd
from .host import HostConfig
from .interface import PhysicalInterfaceConfig
from .sys_helper.cmd_helper import \
        start_sys_cmd_helper, stop_sys_cmd_helper, sys_cmd
from .sys_helper.cmd_helper.manager import SYSCMD_HELPER_SCRIPT


MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')

TMPDIR=os.path.join(os.environ.get('HOME', '.'), 'cougarnet-tmp')
MAIN_FILENAME='_main'
ENV_FILENAME='env'
COMM_SOCK_DIR='comm'
SYS_NET_HELPER_RAW_DIR='helper_sock_raw'
SYS_NET_HELPER_USER_DIR='helper_sock_user'
SYS_CMD_HELPER_SRV='sys_helper_srv'
SYS_CMD_HELPER_DIR='sys_helper'
CONFIG_DIR='config'
HOSTS_DIR='hosts'
SCRIPT_DIR='scripts'
TMUX_DIR='tmux'
SCRIPT_EXTENSION='sh'

SYS_HELPER_MODULE = "cougarnet.virtualnet.sys_helper"

FALSE_STRINGS = ('off', 'no', 'n', 'false', 'f', '0')

VIRT_HOST_STARTUP_TIMEOUT = 6

#XXX this should really be logging.getLogger(__name__), and it should be in
# bin/cougarnet instead
logger = logging.getLogger()

def sort_addresses(addrs):
    '''Sort a list of addresses into MAC address, IPv4 addresses, and IPv6
    addresses, checking them for consistency, and return the sorted elements.'''

    mac_addr = None
    ipv4_addrs = []
    ipv6_addrs = []
    subnet4 = None
    subnet6 = None
    for addr in addrs:
        # MAC address
        m = MAC_RE.search(addr)
        if m is not None:
            if mac_addr is not None:
                raise ConfigurationError('Only one MAC address ' + \
                        'is allowed for a given interface.')
            mac_addr = addr
            continue

        # IP address
        slash = addr.find('/')
        if slash < 0:
            raise ConfigurationError('The IP address for an interface ' + \
                    'must include a prefix length.')

        if ':' in addr:
            # IPv6 address
            try:
                subnet = str(ipaddress.IPv6Network(addr, strict=False))
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
                raise ConfigurationError(str(e)) from None
            if subnet6 is None:
                subnet6 = subnet
            if subnet6 != subnet:
                raise ConfigurationError('All IPv6 addresses for a given ' + \
                        'interface must be on the same subnet.')
            ipv6_addrs.append(addr)
        else:
            # IPv4 address
            try:
                subnet = str(ipaddress.IPv4Network(addr, strict=False))
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
                raise ConfigurationError(str(e)) from None
            if subnet4 is None:
                subnet4 = subnet
            if subnet4 != subnet:
                raise ConfigurationError('All IPv4 addresses for a given ' + \
                        'interface must be on the same subnet.')
            ipv4_addrs.append(addr)
    return mac_addr, ipv4_addrs, ipv6_addrs, subnet4, subnet6

class VirtualNetwork:
    '''The class that creates and manages a Cougarnet Virtual network.'''

    def __init__(self, terminal_hosts, tmpdir, ipv6, verbose):
        self.host_by_name = {}
        self.hostname_by_sock = {}
        self.hosts_file = None
        self.terminal_hosts = terminal_hosts
        self.tmpdir = tmpdir
        self.ipv6 = ipv6
        self.verbose = verbose

        self.bridge_interfaces = set()
        self.ghost_interfaces = set()

        self.comm_dir = os.path.join(self.tmpdir, COMM_SOCK_DIR)
        self.config_dir = os.path.join(self.tmpdir, CONFIG_DIR)
        self.hosts_dir = os.path.join(self.tmpdir, HOSTS_DIR)
        self.script_dir = os.path.join(self.tmpdir, SCRIPT_DIR)
        self.tmux_dir = os.path.join(self.tmpdir, TMUX_DIR)
        self.helper_sock_raw_dir = os.path.join(self.tmpdir, SYS_NET_HELPER_RAW_DIR)
        self.helper_sock_user_dir = os.path.join(self.tmpdir, SYS_NET_HELPER_USER_DIR)
        self.sys_helper_dir = os.path.join(self.tmpdir, SYS_CMD_HELPER_DIR)
        self.helper_local_sock_path = os.path.join(self.sys_helper_dir, MAIN_FILENAME)
        self.env_file = os.path.join(self.tmpdir, ENV_FILENAME)

        self.comm_sock_file = None
        self.comm_sock = None

        for d in self.comm_dir, self.config_dir, self.hosts_dir, \
                self.script_dir, self.tmux_dir, self.helper_sock_raw_dir, \
                self.helper_sock_user_dir, self.sys_helper_dir:
            cmd = ['mkdir', '-p', d]
            subprocess.run(cmd, check=True)

        self._build_env_file()
        self._start_sys_cmd_helper()

    def _build_env_file(self):
        with open(self.env_file, 'w') as fh:
            for key in os.environ:
                fh.write(f'export {key}="{os.environ[key]}"\n')

    def _start_sys_cmd_helper(self):
        remote_sock_path = os.path.join(self.tmpdir, SYS_CMD_HELPER_SRV)

        if not start_sys_cmd_helper(
                remote_sock_path, self.helper_local_sock_path, self.verbose):
            raise StartupError('Could not start system command helper!')

    def parse_int(self, hostname_addr):
        '''Parse a string containing hostname and address information for a
        given interface, and return the parsed information.'''

        parts = hostname_addr.split(',')
        hostname = parts[0]
        addrs = parts[1:]

        mac, addrs4, addrs6, subnet4, subnet6 = \
                sort_addresses(addrs)

        if hostname not in self.host_by_name:
            raise ConfigurationError(f'The specified host is not defined: {hostname}.')
        host = self.host_by_name[hostname]

        if host.type == 'switch' and (mac is not None or addrs4 or addrs6):
            raise ConfigurationError('No addresses are allowed on switches.')

        return host, mac, addrs4, addrs6, subnet4, subnet6

    def import_link(self, line):
        '''Parse a string containing information for a virtual link between two
        virtual hosts.  Instantiate the interfaces and associate them with
        their respective hosts.'''

        parts = line.split(maxsplit=2)
        if len(parts) < 2:
            raise ConfigurationError('Invalid link format.')

        int1_info, int2_info = parts[:2]
        host1, mac1, addrs41, addrs61, subnet41, subnet61 = \
                self.parse_int(int1_info)
        host2, mac2, addrs42, addrs62, subnet42, subnet62 = \
                self.parse_int(int2_info)

        if set(addrs41).intersection(set(addrs42)):
            raise ConfigurationError('The IPv4 addresses for ' + \
                    f'{host1.hostname} and {host2.hostname} ' + \
                    'cannot be the same.')
        if subnet41 is not None and subnet42 is not None and \
                subnet41 != subnet42:
            raise ConfigurationError('The IPv4 addresses for ' + \
                    f'{host1.hostname} and {host2.hostname} ' + \
                    'must be in the same subnet.')
        if set(addrs61).intersection(set(addrs62)):
            raise ConfigurationError('The IPv6 addresses for ' + \
                    f'{host1.hostname} and {host2.hostname} ' + \
                    'cannot be the same.')
        if subnet61 is not None and subnet62 is not None and \
                subnet61 != subnet62:
            raise ConfigurationError('The IPv6 addresses for ' + \
                    f'{host1.hostname} and {host2.hostname} ' + \
                    'must be in the same subnet.')

        if len(parts) > 2:
            s = io.StringIO(parts[2])
            csv_reader = csv.reader(s)
            try:
                attrs = dict([p.split('=', maxsplit=1) \
                        for p in next(csv_reader)])
            except ValueError:
                raise ConfigurationError('Invalid link format.') from None
        else:
            attrs = {}

        int1, int2 = self.add_link(host1, host2, **attrs)
        int1.update(mac_addr=mac1, ipv4_addrs=addrs41, ipv6_addrs=addrs61)
        int2.update(mac_addr=mac2, ipv4_addrs=addrs42, ipv6_addrs=addrs62)

    def import_vlan(self, line):
        '''Parse a string containing information for a VLAN.'''

        parts = line.split()
        if len(parts) != 2:
            raise ConfigurationError('Invalid VLAN format.')

        vlan, host_peer_addr = parts
        parts = host_peer_addr.split(',')

        if len(parts) < 2:
            raise ConfigurationError('Invalid VLAN format; peer switch must be specified.')

        vlan = int(vlan)
        hostname = parts[0]
        peer_hostname = parts[1]
        addrs = parts[2:]

        if hostname not in self.host_by_name:
            raise ConfigurationError(f'The specified host is not defined: {hostname}.')
        host = self.host_by_name[hostname]

        if host.type != 'router':
            raise ConfigurationError('A VLAN interface can only be applied to a router.')

        if peer_hostname not in self.host_by_name:
            raise ConfigurationError(f'The specified host is not defined: {peer_hostname}.')

        if peer_hostname not in host.neighbor_by_hostname:
            raise ConfigurationError('There is no link between the ' + \
                    f'two hosts: {hostname} and {peer_hostname}.')

        neighbor = host.neighbor_by_hostname[peer_hostname]
        phys_int = host.int_by_neighbor[neighbor]

        if not phys_int.trunk:
            raise ConfigurationError('VLAN interface must be linked by a trunk to a switch.')

        mac, addrs4, addrs6 = \
                sort_addresses(addrs)[:3]

        if not (addrs4 or addrs6):
            raise ConfigurationError('At least one IP address is required for a VLAN interface.')

        intf = host.add_vlan(phys_int, vlan)
        intf.update(mac_addr=mac, ipv4_addrs=addrs4, ipv6_addrs=addrs6)

    def process_routes(self):
        '''For every virtual host, parse and store the routes designated by the
        config.'''

        for _, host in self.host_by_name.items():
            host.process_routes()

    @classmethod
    def from_file(cls, fh, terminal_hosts, config_vars, tmpdir, ipv6, verbose):
        '''Read a Cougarnet configuration file containing directives for
        virtual hosts and links, and return the resulting VirtualNetwork
        instance composed of those hosts and links.'''

        net = cls(terminal_hosts, tmpdir, ipv6, verbose)
        mode = None
        lineno = 0
        try:
            for line in fh:
                lineno += 1
                line = line.strip()

                for name, val in config_vars.items():
                    var_re = re.compile(fr'\${name}(\W|$)')
                    line = var_re.sub(fr'{val}\1', line)

                if line == 'NODES':
                    mode = 'node'
                    continue
                if line == 'LINKS':
                    mode = 'link'
                    continue
                if line == 'VLANS':
                    mode = 'vlan'
                    continue
                if not line:
                    continue
                if line.startswith('#'):
                    continue

                if mode == 'node':
                    net.import_node(line)
                elif mode == 'link':
                    net.import_link(line)
                elif mode == 'vlan':
                    net.import_vlan(line)
                else:
                    pass

            net.process_routes()
        except ConfigurationError as e:
            e.lineno = lineno
            raise

        return net

    def import_node(self, line):
        '''Parse a string containing information for a given node--a Host,
        Router, or Switch--and add the instantiated node to the collection
        maintained by this VirtualNetwork instance.'''

        parts = line.split(maxsplit=1)

        hostname = parts[0]
        if not util.is_valid_hostname(hostname):
            raise ConfigurationError(f'The hostname is invalid: {hostname}')
        if hostname == MAIN_FILENAME:
            raise ConfigurationError(f'The hostname is reserved: {hostname}')

        comm_sock_file = os.path.join(self.comm_dir, hostname)
        script_file = os.path.join(self.script_dir, f'{hostname}.sh')
        tmux_file = os.path.join(self.tmux_dir, hostname)
        sys_cmd_helper_local = os.path.join(self.sys_helper_dir, hostname)
        if len(parts) > 1:
            s = io.StringIO(parts[1])
            csv_reader = csv.reader(s)
            try:
                attrs = dict([p.split('=', maxsplit=1) \
                        for p in next(csv_reader)])
            except ValueError:
                raise ConfigurationError('Invalid node format.') from None
        else:
            attrs = {}

        if self.terminal_hosts:
            if hostname in self.terminal_hosts or 'all' in self.terminal_hosts:
                attrs['terminal'] = 'true'
            else:
                attrs['terminal'] = 'false'
        attrs['ipv6'] = str(self.ipv6)

        # check for invalid attributes
        unknown_host_attrs = list(set(attrs).
                difference(set(HostConfig.attrs)))
        if unknown_host_attrs:
            raise ConfigurationError('Invalid host attribute: ' + \
                    f'{unknown_host_attrs[0]}')

        self.hostname_by_sock[comm_sock_file] = hostname
        self.host_by_name[hostname] = \
                HostConfig(hostname, '/dev/null', sys_cmd_helper_local,
                        comm_sock_file, tmux_file, script_file, self.env_file,
                        **attrs)

    def add_link(self, host1, host2, **attrs):
        '''Add a link between two hosts, with the given attributes.  Make sure
        the link configuration is consistent. Instantiate both interfaces, and
        return the resulting objects.'''

        if isinstance(host1, str):
            host1 = self.host_by_name[host1]
        if isinstance(host2, str):
            host2 = self.host_by_name[host2]

        int1_name = f'{host1.hostname}-{host2.hostname}'
        int2_name = f'{host2.hostname}-{host1.hostname}'

        trunk = attrs.get('trunk', None)
        vlan = attrs.get('vlan', None)

        vlan1 = None
        vlan2 = None
        trunk1 = None
        trunk2 = None

        if trunk is not None and vlan is not None:
            raise ConfigurationError('The trunk attribute cannot be used at ' + \
                    'the same time as the vlan attribute.')

        if trunk is not None:
            if not trunk or str(trunk).lower() in FALSE_STRINGS:
                trunk1 = False
                trunk2 = False
            else:
                trunk1 = True
                trunk2 = True

            if not ((host1.type == 'switch' and \
                    host2.type in ('switch', 'router')) or \
                    (host2.type == 'switch' and \
                    host1.type in ('switch', 'router'))):
                raise ConfigurationError('The trunk attribute can only be ' + \
                        'specified when one endpoint is a switch and the ' + \
                        'other is a switch or router')

        if vlan is not None:
            try:
                vlan = int(vlan)
            except ValueError:
                raise ConfigurationError('VLAN value must be an integer.') \
                        from None

            if not (host1.type == 'switch' or host2.type == 'switch'):
                raise ConfigurationError('To assign a VLAN, at least ' + \
                        'one endpoint must be a switch.') from None

            if host1.type == 'switch':
                vlan1 = vlan
                trunk1 = False
            if host2.type == 'switch':
                vlan2 = vlan
                trunk2 = False

        # check for invalid attributes
        unknown_int_attrs = list(set(attrs).
                difference(set(PhysicalInterfaceConfig.attrs)))
        if unknown_int_attrs:
            raise ConfigurationError('Invalid link attribute: ' + \
                    f'{unknown_int_attrs[0]}')

        attrs['vlan'] = vlan1
        attrs['trunk'] = trunk1
        intf1 = host1.add_int(int1_name, host2, **attrs)
        attrs['vlan'] = vlan2
        attrs['trunk'] = trunk2
        intf2 = host2.add_int(int2_name, host1, **attrs)

        # Create the mappings from helper sock to raw- and user-side UNIX
        # socket addresses
        host1.helper_sock_pair_by_int[int1_name] = \
                (os.path.join(self.helper_sock_raw_dir, int1_name),
                        os.path.join(self.helper_sock_user_dir, int1_name))
        host2.helper_sock_pair_by_int[int2_name] = \
                (os.path.join(self.helper_sock_raw_dir, int2_name),
                        os.path.join(self.helper_sock_user_dir, int2_name))

        return intf1, intf2

    def apply_links(self):
        '''Create and connect the virtual interfaces for all the links in this
        VirtualNetwork instance, and put them into their own namespaces, as
        appropriate.'''

        done = set()
        for _, host in self.host_by_name.items():
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
                        raise ConfigurationError(
                                f'Either all links on {host1.hostname} ' + \
                                        'must be designated with a VLAN ' + \
                                        'or as a trunk or none of them must.')
                    host1.has_vlans = has_vlans
                if host2.type == 'switch':
                    has_vlans = bool(int2.vlan is not None or int2.trunk)
                    if has_vlans and host2.has_vlans is False or \
                            not has_vlans and host2.has_vlans:
                        raise ConfigurationError(
                                f'Either all links on {host2.hostname} ' + \
                                        'must be designated with a VLAN ' + \
                                        'or as a trunk or none of them must.')
                    host2.has_vlans = has_vlans

                try:
                    # For each interface, we create both the interface itself and a
                    # "ghost" interface that will be on the host.
                    ghost1 = f'{int1.name}-ghost'
                    ghost2 = f'{int2.name}-ghost'
                    run_cmd('add_link_veth', int1.name, ghost1)
                    run_cmd('add_link_veth', int2.name, ghost2)

                    # We now connect to the two ghost interfaces together with a
                    # bridge.
                    br = f'{int1.name}-br'
                    run_cmd('add_link_bridge', br)
                    run_cmd('set_link_master', ghost1, br)
                    run_cmd('set_link_master', ghost2, br)

                    # These interfaces should have *no* addresses, including IPv6
                    run_cmd('disable_ipv6', ghost1)
                    run_cmd('disable_ipv6', ghost2)
                    run_cmd('disable_ipv6', br)

                    # bring interfaces up
                    run_cmd('set_link_up', ghost1)
                    run_cmd('set_link_up', ghost2)
                    run_cmd('set_link_up', br)
                    self.bridge_interfaces.add(br)
                    self.ghost_interfaces.add(ghost1)
                    self.ghost_interfaces.add(ghost2)

                    if host1.type == 'switch' and host1.native_apps:
                        if not host1.has_bridge:
                            run_cmd('ovs_add_bridge', host1.hostname)
                            host1.has_bridge = True

                        args = [host1.hostname, int1.name]
                        if host1.type == 'switch':
                            if int1.vlan is not None:
                                args.append(int1.vlan)
                            elif int1.trunk:
                                args.append('')
                            else:
                                args.append('0')
                        run_cmd('ovs_add_port', *args)

                    if host2.type == 'switch' and host2.native_apps:
                        if not host2.has_bridge:
                            run_cmd('ovs_add_bridge', host2.hostname)
                            host2.has_bridge = True

                        args = [host2.hostname, int2.name]
                        if host2.type == 'switch':
                            if int2.vlan is not None:
                                args.append(int2.vlan)
                            elif int2.trunk:
                                args.append('')
                            else:
                                args.append('0')
                        run_cmd('ovs_add_port', *args)

                except StartupError as e:
                    raise StartupError('Error creating link ' + \
                            f'{host1.hostname}-{host2.hostname}: {str(e)}') \
                            from None

    def apply_vlans(self):
        '''Create the virtual interfaces associated with a router.'''

        for _, host in self.host_by_name.items():
            for vlan, intf in host.int_by_vlan.items():

                # Sanity check
                if host.type != 'router':
                    raise ConfigurationError(
                            'VLAN interfaces may only be configured on ' + \
                                    'routers; {host.hostname} is not a router.')

                if host.native_apps:
                    run_cmd('add_link_vlan', intf.phys_int.name,
                            intf.name, str(vlan))
                else:
                    run_cmd('add_link_veth', intf.name, '')

    def set_interfaces_up_netns(self):
        '''For each virtual interface, either bring it up (switches in
        native_apps mode) or set the namespace, in which case it will be
        brought up later..'''

        for _, host in self.host_by_name.items():
            for intf in list(host.neighbor_by_int) + \
                    [host.int_by_vlan[i] for i in host.int_by_vlan]:

                if host.type == 'switch' and host.native_apps:
                    # Move interfaces to their appropriate namespaces
                    sys_cmd(['set_link_up', intf.name],
                            check=True)
                else:
                    sys_cmd(['set_link_netns', intf.name, host.hostname],
                            check=True)

    def create_hosts_file(self):
        '''Create a hosts file containing the hostname-address mappings for all
        hosts mananged by the VirtualNetwork instance.'''

        self.hosts_file = os.path.join(self.hosts_dir, MAIN_FILENAME)

        with open(self.hosts_file, 'w') as fh:
            for _, host in self.host_by_name.items():
                host.create_hosts_file_entries(fh)

    def config(self):
        '''Create the files containing network configuration information for
        each host managed by the VirtualNetwork instance.'''

        self.comm_sock_file = os.path.join(self.comm_dir, MAIN_FILENAME)
        self.comm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        self.comm_sock.bind(self.comm_sock_file)

        self.create_hosts_file()
        for hostname, host in self.host_by_name.items():
            config_file = os.path.join(self.config_dir, f'{hostname}.cfg')
            hosts_file = os.path.join(self.hosts_dir, hostname)
            host.create_config(config_file)
            host.create_hosts_file(self.hosts_file, hosts_file)

    def wait_for_phase1_startup(self, host):
        '''Wait for a given virtual host to send its PID over the UNIX domain
        socket designated for communication between VirtualNetwork manager and
        virtual host, as a form of synchronization.  If an invalid PID is sent,
        or if no communication is received within 3 seconds, then raise
        HostNotStarted.'''

        # set to non-bocking with timeout 3
        self.comm_sock.settimeout(3)
        try:
            data, peer = self.comm_sock.recvfrom(16)
            if peer != host.comm_sock_file:
                raise StartupError('While waiting for a communication from ' + \
                        f'{host.hostname}, a packet was received from a ' + \
                        'different virtual host.')
            host.pid = int(data.decode('utf-8'))
        except socket.timeout:
            raise StartupError(f'{host.hostname} did not start properly; ' + \
                    'no communication was received within the designated ' + \
                    'time.') from None
        finally:
            # revert to non-blocking
            self.comm_sock.settimeout(None)

    def wait_for_phase2_startup(self):
        '''Wait for all hosts to send a single null byte (i.e., b'\x00') over
        the UNIX domain socket designated for communication between host and
        virtual hosts, as a form of synchronization.  If any virtual hosts have
        not sent the null byte within 3 seconds, then raise HostNotStarted.'''

        # set to non-bocking with timeout 3
        self.comm_sock.settimeout(VIRT_HOST_STARTUP_TIMEOUT)
        try:
            comm_sock_files = {host.comm_sock_file \
                    for _, host in self.host_by_name.items()}
            start_time = time.time()
            end_time = start_time + VIRT_HOST_STARTUP_TIMEOUT
            while comm_sock_files and time.time() < end_time:
                _, peer = self.comm_sock.recvfrom(1)
                if peer in comm_sock_files:
                    comm_sock_files.remove(peer)
        except socket.timeout:
            pass
        finally:
            # revert to blocking
            self.comm_sock.settimeout(None)

        if not comm_sock_files:
            # we're done!
            return

        # if there were some comm_sock_files left over, map the file to its
        # host, and raise an error
        comm_sock_file_to_hostname = {}
        for hostname, host in self.host_by_name.items():
            comm_sock_file_to_hostname[host.comm_sock_file] = hostname

        for comm_sock_file in comm_sock_files:
            hostname = comm_sock_file_to_hostname[comm_sock_file]
            host = self.host_by_name[hostname]
            cmd = ['ps', '-p', str(host.pid)]
            p = subprocess.run(cmd, stdout=subprocess.DEVNULL, check=False)
            #XXX
            if p.returncode != 0:
                raise StartupError(f'Host {host.hostname} ' + \
                        'terminated early.')
            raise StartupError(f'Host {host.hostname} is taking ' + \
                    'too long to start.')

    def start(self, start_delay, wireshark_ints):
        '''Start the hosts and links comprising the VirtualNetwork instance,
        and synchronize appropriately between the VirtualNetwork instance and
        the virtual hosts.'''

        # start the hosts and wait for each to write its PID to the
        for _, host in self.host_by_name.items():
            host.start(self.comm_sock_file)
            self.wait_for_phase1_startup(host)

        # we have to wait to apply the links until the namespace is created
        # i.e., process has to start, as evidenced by pid file
        self.apply_links()
        self.apply_vlans()
        self.set_interfaces_up_netns()

        # let hosts know that virtual interfaces have been
        # created, so they can proceed with network configuration
        for _, host in self.host_by_name.items():
            self.comm_sock.sendto(b'\x00', host.comm_sock_file)

        self.wait_for_phase2_startup()
        if wireshark_ints:
            self.start_wireshark(wireshark_ints)

        #XXX Debian's connman package ignores and resets disable_ipv6 when
        # bringing up interfaces, so after the interfaces are all up,
        # explicitly disable IPv6 again on all bridge and ghost interfaces, and
        # flush the forwarding table for each.
        # See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1018999
        for intf in self.bridge_interfaces:
            sys_cmd(['disable_ipv6', intf], check=True)
        for intf in self.ghost_interfaces:
            sys_cmd(['disable_ipv6', intf], check=True)
        for _, host in self.host_by_name.items():
            host.flush_forwarding_table()

        # start the raw packet helper for each host
        for _, host in self.host_by_name.items():
            host.start_raw_packet_helper()

        # sleep for start_delay seconds
        time.sleep(start_delay)

        # let hosts know that they can start now
        for _, host in self.host_by_name.items():
            self.comm_sock.sendto(b'\x00', host.comm_sock_file)

        # attach terminals
        for _, host in self.host_by_name.items():
            if host.terminal:
                host.attach_terminal()

    def cleanup(self):
        '''Shut down and clean up resources allocated for the
        VirtualNetwork, including processes, interfaces, and files.'''

        for _, host in self.host_by_name.items():
            host.cleanup()

        for intf in self.bridge_interfaces:
            sys_cmd(['del_link', intf], check=False)

        stop_sys_cmd_helper()

        os.unlink(self.hosts_file)

        self.comm_sock.close()
        os.unlink(self.comm_sock_file)
        os.unlink(self.helper_local_sock_path)
        os.unlink(self.env_file)

        for d in self.comm_dir, self.config_dir, self.hosts_dir, \
                self.script_dir, self.tmux_dir, self.helper_sock_raw_dir, \
                self.helper_sock_user_dir:
            os.rmdir(d)

        # With sys_helper_dir, there might be a race condition in which we try
        # to remove the directory, but the files have not yet been removed.
        # This is because another process removes the remote socket from this
        # directory.  However, even if we fail to remove the directory, the
        # entire tmpfile directory will be removed when the process exits.
        # This is merely due diligence.
        try:
            os.rmdir(self.sys_helper_dir)
        except OSError:
            pass

    def label_for_link(self, host1, int1, host2, int2):
        '''Return a GraphViz label for a given link.'''

        s = '<<TABLE BORDER="0">' + host1.label_for_int(int1) + \
                '<TR><TD COLSPAN="2"></TD></TR>' + \
                host2.label_for_int(int2) + \
                '</TABLE>>'
        return s

    def display_to_file(self, output_file):
        '''Create a GraphViz representation of this VirtualNetwork, and save it
        to a file.'''

        from pygraphviz import AGraph
        G = AGraph()

        done = set()
        for _, host in self.host_by_name.items():
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
        G.draw(output_file, format='png', prog='dot')

    def display_to_screen(self):
        '''Create a GraphViz representation of this VirtualNetwork, and print
        it to standard output.'''

        from pygraphviz import AGraph
        G = AGraph()

        done = set()
        for _, host in self.host_by_name.items():
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
                stderr=subprocess.DEVNULL, check=False)

    def start_wireshark(self, ints):
        '''Start Wireshark, and begin capturing on the specified interfaces.'''

        cmd = ['wireshark']
        for intf in ints:
            cmd += ['-i', intf]
        if ints:
            cmd.append('-k')
        logger.debug(' '.join(cmd))
        subprocess.Popen(cmd)

    def message_loop(self, stop):
        '''Loop until interrupted, printing messages received over the
        communications socket.'''

        show_colors = sys.stdout.isatty() and \
                os.environ.get('TERM', 'dumb') != 'dumb'

        # set to non-bocking with timeout 1
        self.comm_sock.settimeout(1)

        start_time = time.time()
        while True:
            try:
                data, peer = self.comm_sock.recvfrom(4096)
            except socket.timeout:
                if stop is not None and \
                        time.time() - start_time > stop:
                    return
                continue

            msg = data.decode('utf-8')
            if peer is not None:
                hostname = self.hostname_by_sock[peer]
            else:
                hostname = '??'
            ts = time.time() - start_time

            if show_colors:
                print('%000.3f \033[1m%4s\033[0m  %s' % (ts, hostname, msg))
            else:
                print('%000.3f %4s  %s' % (ts, hostname, msg))

def check_requirements(args):
    '''Check the basic requirements for Cougarnet to run, including effective
    user, sudo configuration, presence directories, and presence of certain
    programs.'''

    if os.geteuid() == 0:
        sys.stderr.write('Please run this program as a non-privileged user.\n')
        sys.exit(1)

    try:
        subprocess.run(['sudo', '-k'], check=True)
        subprocess.run(['sudo', '-n', SYSCMD_HELPER_SCRIPT, '-h'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT, check=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write('Please run visudo to allow your user to run ' + \
                f'{SYSCMD_HELPER_SCRIPT} without a password, using the ' + \
                'NOPASSWD option.\n')
        sys.exit(1)

    # make sure working directories exist
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
        subprocess.run(['ovs-vsctl', '-V'], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f'Open vSwitch is required: {str(e)}\n')
        sys.exit(1)

def warn_on_sigttin(sig, frame):
    '''Warn when SIGTTIN is received.  This is only necessary because of some
    issues with extraneous signals being unexpectedly received, possibly a side
    effect of running in a virtual machine.'''

    sys.stderr.write('Warning: SIGTTIN received\n')

def main():
    '''Process command-line arguments, instantiate a VirtualNetwork instance
    from a file, and run and clean-up the virtual network.'''

    parser = argparse.ArgumentParser()
    parser.add_argument('--wireshark', '-w',
            action='store', type=str, default=None,
            metavar='LINKS',
            help='Start wireshark for the specified links ' + \
                    '(host1-host2[,host2-host3,...])')
    parser.add_argument('--verbose', '-v',
            action='store_const', const=True, default=False,
            help='Use verbose output')
    parser.add_argument('--display',
            action='store_const', const=True, default=False,
            help='Display the network configuration as text')
    parser.add_argument('--vars',
            action='store', type=str, default=None,
            help='Specify variables to be replaced in the ' + \
                    'configuration file (name=value[,name=value,...])')
    parser.add_argument('--start',
            action='store', type=int, default=0,
            help='Specify a number of seconds to wait before ' + \
                    'the scenario is started.')
    parser.add_argument('--stop',
            action='store', type=int, default=None,
            help='Specify a number of seconds after which the scenario ' + \
                    'should be halted.')
    parser.add_argument('--terminal',
            action='store', type=str, default=None,
            metavar='HOSTNAMES',
            help='Specify which virtual hosts should launch a terminal ' + \
                    '(all|none|host1[,host2,...])')
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

    # configure logging
    FORMAT = f'%(message)s'
    logger.setLevel(logging.NOTSET)

    if args.verbose:
        h = logging.StreamHandler()
        h.setLevel(logging.DEBUG)
        h.setFormatter(logging.Formatter(fmt=FORMAT))
        logger.addHandler(h)

    check_requirements(args)

    signal.signal(21, warn_on_sigttin)

    try:
        tmpdir = tempfile.TemporaryDirectory(dir=TMPDIR)
    except PermissionError:
        sys.stderr.write('Unable to create working directory.  Check ' + \
                f'permissions of {TMPDIR}.\n')
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

    try:
        net = VirtualNetwork.from_file(args.config_file,
                terminal_hosts, config_vars, tmpdir.name,
                ipv6, args.verbose)
    except ConfigurationError as e:
        sys.stderr.write(f'{args.config_file.name}:{e.lineno}: ' + \
                f'{str(e)}\n')
        sys.exit(1)

    wireshark_ints = []
    if args.wireshark is not None:
        wireshark_ints = args.wireshark.split(',')
        for intf in wireshark_ints:
            intf = intf.strip()
            try:
                host1, host2 = intf.split('-')
            except ValueError:
                sys.stderr.write('Invalid link passed to the ' + \
                        f'--wireshark/-w option: {intf}\n')
                sys.exit(1)
            if host1 not in net.host_by_name:
                sys.stderr.write('Invalid link passed to the ' + \
                        f'--wireshark/-w option; host does not exist: {host1}\n')
                sys.exit(1)
            if host2 not in net.host_by_name:
                sys.stderr.write('Invalid link passed to the ' + \
                        f'--wireshark/-w option; host does not exist: {host2}\n')
                sys.exit(1)
            if host2 not in net.host_by_name[host1].neighbor_by_hostname:
                sys.stderr.write('Invalid link passed to the ' + \
                        f'--wireshark/-w option; link does not exist: {intf}\n')
                sys.exit(1)
        wireshark_ints = [f'{intf}-ghost' for intf in wireshark_ints]

    if args.display:
        net.display_to_screen()
    if args.display_file:
        net.display_to_file(args.display_file)

    err = ''
    try:
        oldmask = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
        net.config()
        net.start(args.start, wireshark_ints)
        signal.pthread_sigmask(signal.SIG_SETMASK, oldmask)
        sys.stdout.write('Ctrl-c to quit\n')
        net.message_loop(args.stop)
    except (StartupError, SysCmdError) as e:
        err = f'{str(e)}\n'
    except KeyboardInterrupt:
        pass
    finally:
        # sometimes ctrl-c gets sent twice, interrupting with SIGINT a second
        # time, and cleanup does not happen.  So here we tell the code to
        # ignore SIGINT, so cleanup can finish.  If you really want to kill it,
        # then use SIGTERM or (gasp!) SIGKILL.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        net.cleanup()

    if err:
        sys.stderr.write(err)
        sys.exit(1)

if __name__ == '__main__':
    main()
