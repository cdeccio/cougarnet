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

class InterfaceInfo:
    def __init__(self, mac_addr, ipv4_addrs, ipv4_prefix_len,
            ipv6_addrs, ipv6_addr_link_local, ipv6_prefix_len, mtu):
        self.mac_addr = mac_addr
        self.ipv4_addrs = [a for a in ipv4_addrs]
        self.ipv4_prefix_len = ipv4_prefix_len
        self.ipv6_addrs = [a for a in ipv6_addrs]
        self.ipv6_addr_link_local = ipv6_addr_link_local
        self.ipv6_prefix_len = ipv6_prefix_len
        self.mtu = mtu
