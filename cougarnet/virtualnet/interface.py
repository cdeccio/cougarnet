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

'''Classes for maintaining configurations related to network interfaces for
virtual hosts.'''

class InterfaceConfig:
    '''Configuration information for a network interface associated with a
    virtual host.'''

    def __init__(self, name, mac_addr=None, ipv4_addrs=None, ipv6_addrs=None,
            bw=None, delay=None, loss=None, mtu=None, vlan=None, trunk=None):

        self.name = name
        self.mac_addr = mac_addr
        self.ipv4_addrs = ipv4_addrs
        self.ipv6_addrs = ipv6_addrs
        self.bw = bw
        self.delay = delay
        self.loss = loss
        self.mtu = mtu
        self.vlan = vlan
        self.trunk = trunk

    def update(self, mac_addr=None, ipv4_addrs=None, ipv6_addrs=None,
            bw=None, delay=None, loss=None, mtu=None, vlan=None, trunk=None):
        '''Update attributes with those specified.'''

        self.mac_addr = mac_addr
        if ipv4_addrs is not None:
            self.ipv4_addrs = ipv4_addrs[:]
        else:
            self.ipv4_addrs = None
        if ipv6_addrs is not None:
            self.ipv6_addrs = ipv6_addrs[:]
        else:
            self.ipv6_addrs = None
        self.bw = bw
        self.delay = delay
        self.loss = loss
        self.mtu = mtu
        self.vlan = vlan
        self.trunk = trunk

    def as_dict(self):
        '''Return a dictionary containing the attributes associated with this
        network instance.'''

        d = {
                'mac_addr': self.mac_addr,
                'bw': self.bw,
                'delay': self.delay,
                'loss': self.loss,
                'mtu': self.mtu,
                'vlan': self.vlan,
                'trunk': self.trunk,
                }

        if self.ipv4_addrs is not None:
            d['ipv4_addrs'] = self.ipv4_addrs[:]
        else:
            d['ipv4_addrs'] = None
        if self.ipv6_addrs is not None:
            d['ipv6_addrs'] = self.ipv6_addrs[:]
        else:
            d['ipv6_addrs'] = None
        return d
