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
