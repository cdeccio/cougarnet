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

class InterfaceConfigBase:
    '''Base class for configuration information for a network interface
    associated with a virtual host.'''

    def __init__(self, name, mac_addr=None, ipv4_addrs=None, ipv6_addrs=None):

        self.name = name
        self.mac_addr = mac_addr
        if ipv4_addrs is not None:
            self.ipv4_addrs = ipv4_addrs[:]
        else:
            self.ipv4_addrs = []
        if ipv6_addrs is not None:
            self.ipv6_addrs = ipv6_addrs[:]
        else:
            self.ipv6_addrs = []

    def update(self, mac_addr=None, ipv4_addrs=None, ipv6_addrs=None):
        '''Update attributes with those specified.'''

        if mac_addr is not None:
            self.mac_addr = mac_addr
        if ipv4_addrs is not None:
            self.ipv4_addrs = ipv4_addrs[:]
        if ipv6_addrs is not None:
            self.ipv6_addrs = ipv6_addrs[:]

    def as_dict(self):
        '''Return a dictionary containing the attributes associated with this
        network interface instance.'''

        return {
                'mac_addr': self.mac_addr,
                'ipv4_addrs': self.ipv4_addrs,
                'ipv6_addrs': self.ipv6_addrs,
                }

class PhysicalInterfaceConfig(InterfaceConfigBase):
    '''Configuration information for a "physical" network interface associated
    with a virtual host.'''

    def __init__(self, name, mac_addr=None, ipv4_addrs=None, ipv6_addrs=None,
            bw=None, delay=None, loss=None, mtu=None, vlan=None, trunk=None):

        super(PhysicalInterfaceConfig, self).__init__(
                name, mac_addr, ipv4_addrs, ipv6_addrs)

        self.bw = bw
        self.delay = delay
        self.loss = loss
        self.mtu = mtu
        self.vlan = vlan
        self.trunk = trunk

    def update(self, mac_addr=None, ipv4_addrs=None, ipv6_addrs=None,
            bw=None, delay=None, loss=None, mtu=None, vlan=None, trunk=None):
        '''Update attributes with those specified.'''

        super(PhysicalInterfaceConfig, self).update(
                mac_addr, ipv4_addrs, ipv6_addrs)

        if bw is not None:
            self.bw = bw
        if delay is not None:
            self.delay = delay
        if loss is not None:
            self.loss = loss
        if mtu is not None:
            self.mtu = mtu
        if vlan is not None:
            self.vlan = vlan
        if trunk is not None:
            self.trunk = trunk

    def as_dict(self):
        '''Return a dictionary containing the attributes associated with this
        network instance.'''

        d = super(PhysicalInterfaceConfig, self).as_dict()
        d.update({
                'bw': self.bw,
                'delay': self.delay,
                'loss': self.loss,
                'mtu': self.mtu,
                'vlan': self.vlan,
                'trunk': self.trunk,
                })
        return d
