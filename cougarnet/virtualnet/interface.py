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

class InterfaceConfig(object):
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

        self.mac_addr = mac_addr
        self.ipv4_addrs = [a for a in ipv4_addrs]
        self.ipv6_addrs = [a for a in ipv6_addrs]
        self.bw = bw
        self.delay = delay
        self.loss = loss
        self.mtu = mtu
        self.vlan = vlan
        self.trunk = trunk

    def as_dict(self):
        return {
                'mac_addr': self.mac_addr,
                'ipv4_addrs': [a for a in self.ipv4_addrs],
                'ipv6_addrs': [a for a in self.ipv6_addrs],
                'bw': self.bw,
                'delay': self.delay,
                'loss': self.loss,
                'mtu': self.mtu,
                'vlan': self.vlan,
                'trunk': self.trunk,
                }
