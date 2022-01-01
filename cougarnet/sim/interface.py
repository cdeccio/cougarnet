class InterfaceInfo:
    def __init__(self, macaddr, ipv4addrs, ipv4prefix, ipv4broadcast, \
            ipv6addrs, ipv6lladdr, ipv6prefix, mtu):
        self.macaddr = macaddr
        self.ipv4addrs = ipv4addrs
        self.ipv4prefix = ipv4prefix
        self.ipv4broadcast = ipv4broadcast
        self.ipv6addrs = ipv6addrs
        self.ipv6lladdr = ipv6lladdr
        self.ipv6prefix = ipv6prefix
        self.mtu = mtu

