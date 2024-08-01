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

'''A class that holds various fields related to an interface.'''


class InterfaceInfo:
    '''A class that holds various fields related to an interface.'''

    def __init__(self, mac_addr, ipv4_addrs, ipv4_prefix_len,
                 ipv6_addrs, ipv6_addr_link_local, ipv6_prefix_len, mtu):
        self.mac_addr = mac_addr
        self.ipv4_addrs = [a for a in ipv4_addrs]
        self.ipv4_prefix_len = ipv4_prefix_len
        self.ipv6_addrs = [a for a in ipv6_addrs]
        self.ipv6_addr_link_local = ipv6_addr_link_local
        self.ipv6_prefix_len = ipv6_prefix_len
        self.mtu = mtu
        self.vlan = None
