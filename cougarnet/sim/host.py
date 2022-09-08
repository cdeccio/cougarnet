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

'''A base class for classes running network host-like functionality in a
virtual host environment.'''

import asyncio
import json
import os
import re
import socket
import subprocess

from cougarnet.util import recv_raw, ETH_P_ALL, SOL_PACKET, PACKET_AUXDATA
from .interface import InterfaceInfo

IP_ADDR_MTU_RE = re.compile(r'^\d:\s+.*\smtu\s+(\d+)(\s|$)')
IP_ADDR_MAC_RE = re.compile(r'^\s+link/ether\s+' + \
        r'([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})(\s|$)')
IP_ADDR_IPV4_RE = re.compile(r'^\s+inet\s+([0-9]{1,3}(\.[0-9]{1,3}){3})' + \
        r'\/(\d{1,2})\s+brd\s+([0-9]{1,3}(\.[0-9]{1,3}){3})(\s|$)')
IP_ADDR_IPV6_RE = re.compile(r'^\s+inet6\s+([0-9a-f:]+)\/(\d{1,3})\s.*' + \
        r'scope\s+(link|global)(\s|$)')
VLAN_INT_NAME_RE = re.compile(r'\.vlan(\d+)$')

class BaseHost:
    '''A base class for classes running network host-like functionality in a
    virtual host environment.  It gathers information on all the interfaces
    associated with this virtual host, sets up the raw sockets for each
    interface for send/recv functions, and sets up logging with the cougarnet
    process.'''

    def __init__(self, user_mode=True):
        self.all_interfaces = []
        self.physical_interfaces = []
        self.vlan_interfaces = []
        self.int_to_sock = {}
        self.int_to_info = {}

        self.hostname = socket.gethostname()

        self._setup_comm_sock()

        if user_mode:
            self._setup_sockets_user()
        else:
            self._setup_sockets_raw()
        self._detect_interfaces()
        self._set_interface_info()
        self._set_vlan_info()

    def __enter__(self):
        '''Simply return the object.'''

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        '''Call cleanup to clean resources on exit.'''

        self.cleanup()

    def cleanup(self):
        '''Clean up by removing the files associated with the communication
        socket and the raw packet helper sockets.'''

        self._remove_comm_sock()
        self._remove_helper_socks()

    def _remove_comm_sock(self):
        '''Attempt to remove the file associated with the socket used for
        logging to the cougarnet process.'''

        try:
            comm_sock_paths = json.loads(os.environ['COUGARNET_COMM_SOCK'])
            os.unlink(comm_sock_paths['local'])
        except FileNotFoundError:
            pass

    def _remove_helper_socks(self):
        '''Attempt to remove the files associated with the sockets used for
        communicating with raw packet helper process.'''

        helper_socks = json.loads(os.environ['COUGARNET_INT_TO_SOCK'])
        for intf in helper_socks:
            try:
                os.unlink(helper_socks[intf]['local'])
            except FileNotFoundError:
                pass

    def _setup_comm_sock(self):
        '''Create and configure the socket used for logging to the cougarnet
        process.'''

        comm_sock_paths = json.loads(os.environ['COUGARNET_COMM_SOCK'])
        self.comm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        self.comm_sock.connect(comm_sock_paths['remote'])
        self.comm_sock.bind(comm_sock_paths['local'])

    def _detect_interfaces(self):
        self.all_interfaces = os.listdir('/sys/class/net/')
        self.physical_interfaces = [i for i in self.all_interfaces \
            if not i.startswith('lo') and VLAN_INT_NAME_RE.search(i) is None]
        self.vlan_interfaces = [i for i in self.all_interfaces \
            if not i.startswith('lo') and VLAN_INT_NAME_RE.search(i) is not None]

    def _setup_sockets_raw(self):
        '''Create and configure a raw socket for send/recv on each
        interface.'''

        loop = asyncio.get_event_loop()
        for intf in self.physical_interfaces:

            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((intf, 0))
            sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)

            sock.setblocking(False)
            loop.add_reader(sock, self._handle_incoming_data_raw, sock, intf)

            self.int_to_sock[intf] = sock

    def _setup_sockets_user(self):
        '''Create and configure a the UNIX domain sockets used for send/recv on
        each interface.  The messages send on these sockets will be received by
        a helper process and then sent on the raw socket corresponding to the
        interface.'''

        int_sock_mapping = json.loads(os.environ['COUGARNET_INT_TO_SOCK'])

        loop = asyncio.get_event_loop()
        for intf in self.physical_interfaces:

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
            sock.connect(int_sock_mapping[intf]['remote'])
            sock.bind(int_sock_mapping[intf]['local'])

            sock.setblocking(False)
            loop.add_reader(sock, self._handle_incoming_data_user, sock, intf)

            self.int_to_sock[intf] = sock

    @classmethod
    def _get_interface_info(cls, intf):
        '''Retrieve the information for a given interface (i.e., using the "ip
        addr" command), instantiate an InterfaceInfo object, and return it.'''

        mac_addr = None
        mtu = None
        ipv4_prefix_len = None
        ipv4_broadcast = None
        ipv4_addrs = []
        ipv6_prefix_len = None
        ipv6_addrs = []
        ipv6_addr_link_local = None
        p = subprocess.run(['ip', 'addr', 'show', intf],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=True)
        output = p.stdout.decode('utf-8')
        for line in output.splitlines():
            m = IP_ADDR_MAC_RE.match(line)
            if m is not None:
                # MAC address
                mac_addr = m.group(1)
                continue

            m = IP_ADDR_IPV4_RE.match(line)
            if m is not None:
                # IPv4 address
                ipv4_addrs.append(m.group(1))
                ipv4_prefix_len = int(m.group(3))
                ipv4_broadcast = m.group(4)
                continue

            m = IP_ADDR_IPV6_RE.match(line)
            if m is not None:
                # IPv6 address
                if m.group(3) == 'global':
                    # IPv6 global address
                    ipv6_addrs.append(m.group(1))
                    ipv6_prefix_len = int(m.group(2))
                elif m.group(3) == 'link':
                    # IPv6 link-local address
                    ipv6_addr_link_local = m.group(1)
                continue

            m = IP_ADDR_MTU_RE.match(line)
            if m is not None:
                mtu = int(m.group(1))

        return InterfaceInfo(mac_addr, ipv4_addrs, ipv4_prefix_len,
                        ipv6_addrs, ipv6_addr_link_local, ipv6_prefix_len, mtu)

    def _is_trunk_link(self, intf):
        '''Return True if the given interface is on a trunk link; False
        otherwise.'''

        return self.int_to_info[intf].vlan is not None and \
                self.int_to_info[intf].vlan < 0

    def _handle_frame(self, frame, intf):
        '''Handle an incoming frame (bytes) received on the given interface
        (str).  This method is called as a callback every time a frame is
        received.  It is intended to be overridden by a child class.'''

    def _handle_incoming_data_user(self, sock, intf):
        '''Receive one or more Ethernet frames from the specified UNIX domain
        socket, corresponding to the given interface.  Call _handle_frame() for
        each frame received.'''

        while True:
            try:
                frame = sock.recv(4096)
            except BlockingIOError:
                return
            self._handle_frame(frame, intf)

    def _handle_incoming_data_raw(self, sock, intf):
        '''Receive one or more Ethernet frames from the specified raw socket,
        corresponding to the given interface.  Call _handle_frame() for each
        frame received.'''

        while True:
            try:
                frame, info = recv_raw(sock, 4096)
            except BlockingIOError:
                return
            (ifname, proto, pkttype, hatype, addr) = info
            if pkttype == socket.PACKET_OUTGOING:
                continue
            self._handle_frame(frame, intf)

    def _set_interface_info(self):
        '''Populate the information for each interface by calling
        self._get_interface_info() on each.'''

        for intf in self.all_interfaces:
            self.int_to_info[intf] = self._get_interface_info(intf)

    def _set_vlan_info(self):
        '''Set the VLAN for each interface by using the environment variable
        set by cougarnet.'''

        info = json.loads(os.environ.get('COUGARNET_VLAN', '{}'))

        if info:
            non_vlan_interfaces = set(self.physical_interfaces)
            interfaces_from_env = set(info)

            # Sanity check
            if non_vlan_interfaces.difference(interfaces_from_env):
                raise ValueError('Not all interfaces from /sys/class/net ' + \
                        'exist in COUGARNET_VLAN!')
            if interfaces_from_env.difference(non_vlan_interfaces):
                raise ValueError('Not all interfaces in COUGARNET_VLAN ' + \
                        'exist in /sys/class/net!')

            for intf in info:
                if info[intf].startswith('vlan'):
                    self.int_to_info[intf].vlan = \
                            int(info[intf].replace('vlan', ''))
                elif info[intf] == 'trunk':
                    self.int_to_info[intf].vlan = -1
        else:
            for intf in self.int_to_info:
                self.int_to_info[intf].vlan = 0

    def get_interface(self):
        '''Get the name of the single interface associated with this host.
        Note that this is meant to be used as a convenience method for systems
        with a single interface.'''

        if len(self.int_to_sock) > 1:
            raise ValueError('There is more than one interface on ' + \
                    f'{self.hostname}')
        try:
            return [i for i in self.int_to_sock][0]
        except IndexError:
            return None

    def send_frame(self, frame, intf):
        '''Send a single frame (bytes) on the given interface, intf (str).'''

        self.int_to_sock[intf].send(frame)

    def log(self, msg):
        '''Log a message, msg (str), by sending it to the socket designated for
        communications to the cougarnet process.'''

        self.comm_sock.send(msg.encode('utf-8'))
