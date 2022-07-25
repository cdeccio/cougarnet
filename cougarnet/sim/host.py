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

import asyncio
import json
import os
import re
import socket
import subprocess

from .interface import InterfaceInfo

IP_ADDR_MTU_RE = re.compile(r'^\d:\s+.*\smtu\s+(\d+)(\s|$)')
IP_ADDR_MAC_RE = re.compile(r'^\s+link/ether\s+([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})(\s|$)')
IP_ADDR_IPV4_RE = re.compile(r'^\s+inet\s+([0-9]{1,3}(\.[0-9]{1,3}){3})\/(\d{1,2})\s+brd\s+([0-9]{1,3}(\.[0-9]{1,3}){3})(\s|$)')
IP_ADDR_IPV6_RE = re.compile(r'^\s+inet6\s+([0-9a-f:]+)\/(\d{1,3})\s.*scope\s+(link|global)(\s|$)')

from cougarnet.util import recv_raw, ETH_P_ALL, SOL_PACKET, PACKET_AUXDATA

class BaseHost:
    def __init__(self):
        self.int_to_sock = {}
        self.int_to_info = {}

        self.hostname = socket.gethostname()
        self._setup_send_sockets()
        self._setup_receive_sockets()

        self._setup_comm_sock()

        self._set_interface_info()

    def __del__(self):
        self._remove_comm_sock()

    def _remove_comm_sock(self):
        try:
            comm_sock_paths = json.loads(os.environ['COUGARNET_COMM_SOCK'])
            os.unlink(comm_sock_paths['local'])
        except FileNotFoundError:
            pass

    def _setup_comm_sock(self):
        comm_sock_paths = json.loads(os.environ['COUGARNET_COMM_SOCK'])
        self.comm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        self.comm_sock.connect(comm_sock_paths['remote'])
        self.comm_sock.bind(comm_sock_paths['local'])

    def _setup_receive_sockets(self):
        loop = asyncio.get_event_loop()
        ints = os.listdir('/sys/class/net/')
        for intf in ints:

            #XXX this is a hack. fix this by putting it in its own namespace
            #if intf.startswith('lo'):
            #    continue
            if not intf.startswith(f'{self.hostname}-'):
                continue

            # For receiving...
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((intf, 0))
            sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)

            sock.setblocking(False)
            loop.add_reader(sock, self._handle_incoming_data, sock, intf)

    def _setup_send_sockets(self):
        ints = os.listdir('/sys/class/net/')
        for intf in ints:
            #XXX this is a hack. fix this by putting it in its own namespace
            #if intf.startswith('lo'):
            #    continue
            if not intf.startswith(f'{self.hostname}-'):
                continue

            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((intf, 0))
            self.int_to_sock[intf] = sock

    @classmethod
    def _get_interface_info(cls, intf):
        mac_addr = None
        mtu = None
        ipv4_prefix_len = None
        ipv4_broadcast = None
        ipv4_addrs = []
        ipv6_prefix_len = None
        ipv6_addrs = []
        ipv6_addr_link_local = None
        output = subprocess.run(['ip', 'addr', 'show', intf], \
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
        output = output.decode('utf-8')
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

    def _handle_frame(self, frame, intf):
        pass

    def _handle_incoming_data(self, sock, intf):
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
        for intf in self.int_to_sock:
            self.int_to_info[intf] = self._get_interface_info(intf)

    def get_interface(self):
        if len(self.int_to_sock) > 1:
            raise ValueError(f'There is more than one interface on ' + \
                    f'{self.hostname}')
        try:
            return [i for i in self.int_to_sock][0]
        except IndexError:
            return None

    def send_frame(self, frame, intf):
        self.int_to_sock[intf].send(frame)

    def log(self, msg):
        self.comm_sock.send(msg.encode('utf-8'))
