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
