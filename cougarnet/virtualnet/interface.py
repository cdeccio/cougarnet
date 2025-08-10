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

'''Classes for maintaining configurations related to network interfaces for
virtual hosts.'''

class InterfaceConfigBase:
    '''Base class for configuration information for a network interface
    associated with a virtual host.'''

    def __init__(self, name, ipv4_addrs=None, ipv6_addrs=None):

        self.name = name
        if ipv4_addrs is not None:
            self.ipv4_addrs = ipv4_addrs[:]
        else:
            self.ipv4_addrs = []
        if ipv6_addrs is not None:
            self.ipv6_addrs = ipv6_addrs[:]
        else:
            self.ipv6_addrs = []

    def update(self, ipv4_addrs=None, ipv6_addrs=None):
        '''Update attributes with those specified.'''

        if ipv4_addrs is not None:
            self.ipv4_addrs = ipv4_addrs[:]
        if ipv6_addrs is not None:
            self.ipv6_addrs = ipv6_addrs[:]

    def as_dict(self):
        '''Return a dictionary containing the attributes associated with this
        network interface instance.'''

        return {
                'ipv4_addrs': self.ipv4_addrs,
                'ipv6_addrs': self.ipv6_addrs,
                }

class LoopbackInterfaceConfig(InterfaceConfigBase):
    pass

class InterfaceWithMacAddrConfig(InterfaceConfigBase):
    '''Class for configuration information for a network interface that has a
    MAC address.'''

    def __init__(self, name, mac_addr=None, ipv4_addrs=None, ipv6_addrs=None):

        super().__init__(name, ipv4_addrs, ipv6_addrs)

        self.mac_addr = mac_addr

    def update(self, mac_addr=None, ipv4_addrs=None, ipv6_addrs=None):
        '''Update attributes with those specified.'''

        if mac_addr is not None:
            self.mac_addr = mac_addr
        super().update(ipv4_addrs, ipv6_addrs)

    def as_dict(self):
        '''Return a dictionary containing the attributes associated with this
        network interface instance.'''

        d = super().as_dict()
        d['mac_addr'] = self.mac_addr
        return d

class PhysicalInterfaceConfig(InterfaceWithMacAddrConfig):
    '''Configuration information for a "physical" network interface associated
    with a virtual host.'''

    attrs = { 'bw': None,
            'delay': None,
            'loss': None,
            'mtu': None,
            'vlan': None,
            'trunk': None,
            }

    def __init__(self, name, mac_addr=None, ipv4_addrs=None, ipv6_addrs=None,
            **kwargs):

        super().__init__(name, mac_addr, ipv4_addrs, ipv6_addrs)

        for attr in self.__class__.attrs:
            setattr(self, attr, kwargs.get(attr, self.__class__.attrs[attr]))

    def update(self, mac_addr=None, ipv4_addrs=None, ipv6_addrs=None,
            **kwargs):
        '''Update attributes with those specified.'''

        super().update(mac_addr, ipv4_addrs, ipv6_addrs)

        for attr in kwargs:
            setattr(self, attr, kwargs[attr])

    def as_dict(self):
        '''Return a dictionary containing the attributes associated with this
        network instance.'''

        d = super().as_dict()
        for attr in self.__class__.attrs:
            d[attr] = getattr(self, attr)
        return d

class VirtualInterfaceConfig(InterfaceWithMacAddrConfig):
    '''Configuration information for a virtual network interface associated
    with a virtual host, i.e., for a VLAN.'''

    def __init__(self, phys_int, vlan, mac_addr=None, ipv4_addrs=None,
            ipv6_addrs=None):

        name = f'{phys_int.name}.vlan{vlan}'
        super().__init__(name, mac_addr, ipv4_addrs, ipv6_addrs)
        self.phys_int = phys_int
