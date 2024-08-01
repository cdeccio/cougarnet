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
import socket

from pyroute2.ndb.main import NDB

from cougarnet.util import recv_raw, ETH_P_ALL, SOL_PACKET, PACKET_AUXDATA
from cougarnet.sys_helper.cmd_helper import \
        join_sys_cmd_helper, stop_sys_cmd_helper


class BaseHost:
    '''A base class for classes running network host-like functionality in a
    virtual host environment.  It gathers information on all the interfaces
    associated with this virtual host, sets up the raw sockets for each
    interface for send/recv functions, and sets up logging with the cougarnet
    process.'''

    def __init__(self, user_mode=True):
        self.int_to_sock = {}
        self.int_to_vlan = {}
        self.vlan_to_int = {}

        self._ndb = NDB()

        self._pending_frames = {}

        self.hostname = socket.gethostname()

        self._setup_comm_sock()
        self._join_sys_cmd_helper()

        self._set_vlan_info()

        if user_mode:
            self._setup_sockets_user()
        else:
            self._setup_sockets_raw()

    def cleanup(self):
        '''Clean up by removing the files associated with the communication
        socket and the raw packet helper sockets.'''

        self._remove_comm_sock()
        self._remove_helper_socks()
        self._stop_sys_cmd_helper()

    def _join_sys_cmd_helper(self):
        helper_sock_paths = \
                json.loads(os.environ['COUGARNET_SYS_CMD_HELPER_SOCK'])
        if not join_sys_cmd_helper(
                helper_sock_paths['remote'], helper_sock_paths['local'],
                add_pid_for_netns=True):
            # XXX need something more specific here
            raise Exception('Could not connect to command helper socket')

    def _stop_sys_cmd_helper(self):
        stop_sys_cmd_helper()

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

    @classmethod
    def _return_one(cls, func, args, kwargs):
        '''Call a specified function with the given args and kwargs.  If there
        are no results or multiple results, then return an error.  Otherwise,
        return the single result.'''

        val = func(*args, **kwargs)
        if len(val) == 0:
            raise ValueError('There are none.')
        if len(val) > 1:
            raise ValueError('There is more than one.')
        return val[0]

    def interfaces_info(self, intf=None, **kwargs):
        '''Return the list of dictionary-like objects for all interfaces on the
        (virtual) system having the specified attributes (or all interfaces, if
        intf and kwargs are empty).'''

        if intf is not None:
            kwargs['ifname'] = intf
        return [obj for obj in
                self._ndb.interfaces.dump().filter(**kwargs)]

    def interface_info_single(self, intf):
        '''Return the dictionary-like object correponding to the interface with
        the specified interface name, or None, if that interface doesn't
        exist.'''

        try:
            return self.interfaces_info(intf)[0]
        except IndexError:
            return None

    def physical_interfaces_info(self, **kwargs):
        '''Return the list of dictionary-like objects for all "physical"
        (non-VLAN) interfaces on the (virtual) system having the specified
        attributes (or all interfaces, if kwargs is empty).'''

        if 'kind' in kwargs:
            del kwargs['kind']
        return self.interfaces_info(kind='veth', **kwargs)

    def physical_interface_info_single(self):
        '''Return the dictionary-like object correponding to the one-and-only
        "physical" (non-VLAN) interface on the (virtual) system.  Raise
        ValueError if there are no physical interfaces or if there is more than
        one physical interface.'''

        return self._return_one(self.physical_interfaces_info, (), {})

    def vlan_interfaces_info(self, **kwargs):
        '''Return the list of dictionary-like objects for all VLAN interfaces
        on the (virtual) system having the specified attributes (or all
        interfaces, if kwargs is empty).'''

        if 'kind' in kwargs:
            del kwargs['kind']
        return self.interfaces_info(kind='vlan', **kwargs)

    def interfaces(self, **kwargs):
        '''Return the list of interface names for all interfaces on the
        (virtual) system having the specified attributes (or all interfaces, if
        kwargs is empty).'''

        return [i['ifname'] for i in self.interfaces_info(**kwargs)]

    def physical_interfaces(self, **kwargs):
        '''Return the list of interface names for all "physical" (non-VLAN)
        interfaces on the (virtual) system having the specified attributes (or
        all interfaces, if kwargs is empty).'''

        return [i['ifname'] for i in self.physical_interfaces_info(**kwargs)]

    def physical_interface_single(self):
        '''Return the interface name correponding to the one-and-only
        "physical" (non-VLAN) interface on the (virtual) system.  Raise
        ValueError if there are no physical interfaces or if there is more than
        one physical interface.'''

        return self._return_one(self.physical_interfaces, (), {})

    def vlan_interfaces(self, **kwargs):
        '''Return the list of interface names for all VLAN interfaces on the
        (virtual) system having the specified attributes (or all interfaces, if
        kwargs is empty).'''

        return [i['ifname'] for i in self.vlan_interfaces_info(**kwargs)]

    def addresses_info(self, intf=None, **kwargs):
        '''Return the list of dictionary-like objects for all IP addresses on
        the (virtual) system having the specified attributes (or all IP
        addresses, if intf and kwargs are empty).'''

        if intf is None:
            q = self._ndb.addresses
        else:
            q = self._ndb.interfaces[intf].ipaddr
        return [obj for obj in q.dump().filter(**kwargs)]

    def ipv4_addresses_info(self, intf=None, **kwargs):
        '''Return the list of dictionary-like objects for all IPv4 addresses on
        the (virtual) system having the specified attributes (or all IPv4
        addresses, if intf and kwargs are empty).'''

        if 'family' in kwargs:
            del kwargs['family']
        return self.addresses_info(intf=intf, family=socket.AF_INET, **kwargs)

    def ipv6_addresses_info(self, intf=None, **kwargs):
        '''Return the list of dictionary-like objects for all IPv6 addresses on
        the (virtual) system having the specified attributes (or all IPv6
        addresses, if intf and kwargs are empty).'''

        if 'family' in kwargs:
            del kwargs['family']
        return self.addresses_info(intf=intf, family=socket.AF_INET6, **kwargs)

    def ipv4_address_info_single(self, intf):
        '''Return the dictionary-like object for the one-and-only IPv4 address
        for the specified interface.  Raise ValueError if there are no IPv4
        addresses on the specified interface or if there is more than one IPv4
        address on that interface.'''

        return self._return_one(self.ipv4_addresses_info, (intf,), {})

    def ipv6_address_info_single(self, intf):
        '''Return the dictionary-like object for the one-and-only IPv6 address
        for the specified interface.  Raise ValueError if there are no IPv6
        addresses on the specified interface or if there is more than one IPv6
        address on that interface.'''

        return self._return_one(self.ipv6_addresses_info, (intf,), {})

    def addresses(self, intf=None, **kwargs):
        '''Return the list of IP addresses on the (virtual) system having the
        specified attributes (or all IP addresses, if intf and kwargs are
        empty).'''

        return [a['address'] for a in self.addresses_info(intf=intf, **kwargs)]

    def ipv4_addresses(self, intf=None, **kwargs):
        '''Return the list of IPv4 addresses on the (virtual) system having the
        specified attributes (or all IPv4 addresses, if intf and kwargs are
        empty).'''

        return [a['address'] for a in
                self.ipv4_addresses_info(intf=intf, **kwargs)]

    def ipv6_addresses(self, intf=None, **kwargs):
        '''Return the list of IPv6 addresses on the (virtual) system having the
        specified attributes (or all IPv6 addresses, if intf and kwargs are
        empty).'''

        return [a['address'] for a in
                self.ipv6_addresses_info(intf=intf, **kwargs)]

    def ipv4_address_single(self, intf):
        '''Return the one-and-only IPv4 address for the specified interface.
        Raise ValueError if there are no IPv4 addresses on the specified
        interface or if there is more than one IPv4 address on that
        interface.'''

        return self._return_one(self.ipv4_addresses, (intf,), {})

    def ipv6_address_single(self, intf):
        '''Return the one-and-only IPv6 address for the specified interface.
        Raise ValueError if there are no IPv6 addresses on the specified
        interface or if there is more than one IPv6 address on that
        interface.'''

        return self._return_one(self.ipv6_addresses, (intf,), {})

    def _setup_sockets_raw(self):
        '''Create and configure a raw socket for send/recv on each
        interface.'''

        loop = asyncio.get_event_loop()
        for intf in self.physical_interfaces():
            sock = socket.socket(socket.AF_PACKET,
                                 socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((intf, 0))
            sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)

            sock.setblocking(False)
            loop.add_reader(sock, self._handle_incoming_data_raw, sock, intf)

            self.int_to_sock[intf] = sock
            self._pending_frames[intf] = []

    def _setup_sockets_user(self):
        '''Create and configure a the UNIX domain sockets used for send/recv on
        each interface.  The messages send on these sockets will be received by
        a helper process and then sent on the raw socket corresponding to the
        interface.'''

        int_sock_mapping = json.loads(os.environ['COUGARNET_INT_TO_SOCK'])

        loop = asyncio.get_event_loop()
        for intf in self.physical_interfaces():

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
            sock.connect(int_sock_mapping[intf]['remote'])
            sock.bind(int_sock_mapping[intf]['local'])

            sock.setblocking(False)
            loop.add_reader(sock, self._handle_incoming_data_user, sock, intf)

            self.int_to_sock[intf] = sock
            self._pending_frames[intf] = []

    def is_trunk_link(self, intf):
        '''Return True if the given interface is on a trunk link; False
        otherwise.'''

        return self.int_to_vlan[intf] < 0

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

    def _set_vlan_info(self):
        '''Set the VLAN for each interface by using the environment variable
        set by cougarnet.'''

        info = json.loads(os.environ.get('COUGARNET_VLAN', '{}'))

        physical_interfaces = self.physical_interfaces()
        if not info:
            for intf in physical_interfaces:
                info[intf] = 'vlan0'

        non_vlan_interfaces = set(physical_interfaces)
        interfaces_from_env = set(info)

        # Sanity check
        if non_vlan_interfaces.difference(interfaces_from_env):
            raise ValueError('Not all interfaces from NDB ' +
                             'exist in COUGARNET_VLAN!')
        if interfaces_from_env.difference(non_vlan_interfaces):
            raise ValueError('Not all interfaces in COUGARNET_VLAN ' +
                             'exist in NDB!')

        for intf in info:
            if info[intf].startswith('vlan'):
                vlan = int(info[intf].replace('vlan', ''))
            elif info[intf] == 'trunk':
                vlan = -1
            else:
                raise ValueError('Invalid value for VLAN: %s' % info[intf])
            self.int_to_vlan[intf] = vlan
            if vlan not in self.vlan_to_int:
                self.vlan_to_int[vlan] = []
            self.vlan_to_int[vlan].append(intf)

    @property
    def trunk_links(self):
        return self.vlan_to_int[-1]

    def send_frame(self, frame, intf):
        '''Send a single frame (bytes) on the given interface, intf (str).'''

        try:
            self.int_to_sock[intf].send(frame)
        except BlockingIOError:
            self._pending_frames[intf].append((frame, self.int_to_sock[intf]))
            loop = asyncio.get_event_loop()
            loop.add_writer(self.int_to_sock[intf],
                            self._send_pending_frames, intf)

    def _send_pending_frames(self, intf):
        '''Send all frames that are pending, until blocking might occur.'''

        loop = asyncio.get_event_loop()
        try:
            i = 0
            for frame, sock in self._pending_frames[intf]:
                sock.send(frame)
                i += 1
        except BlockingIOError:
            pass
        else:
            loop.remove_writer(self.int_to_sock[intf])
        for _ in range(i):
            self._pending_frames[intf].pop(0)

    def log(self, msg):
        '''Log a message, msg (str), by sending it to the socket designated for
        communications to the cougarnet process.'''

        self.comm_sock.send(msg.encode('utf-8'))

    def run(self):
        '''Let the object handle events until interrupted.'''

        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            loop.close()
            self.cleanup()
