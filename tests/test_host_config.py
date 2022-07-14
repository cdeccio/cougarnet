import io
import tempfile
import unittest

from cougarnet.virtualnet.manager import ConfigurationError
from cougarnet.virtualnet.manager import VirtualNetwork
from cougarnet.virtualnet.manager import MAIN_FILENAME

class BadConfigTestCase(unittest.TestCase):
    def test_host_config_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:

                # Invalid hostname (1)
                cfg = io.StringIO('NODES\n1h')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid hostname (2)
                cfg = io.StringIO('NODES\n{MAIN_FILENAME}')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid host attribute format (should be foo=bar)
                cfg = io.StringIO('NODES\nh1 foo')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid host attribute (foo)
                cfg = io.StringIO('NODES\nh1 foo=bar')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

    def test_host_attrs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with tempfile.NamedTemporaryFile('w+', prefix='cougarnet', \
                    delete=True) as cfg:

                # Node with default attributes
                cfg = io.StringIO('NODES\nh1')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                self.assertEqual(net.host_by_name['h1']._host_config(),
                        {'hostname': 'h1',
                            'interfaces': {},
                            'ip_forwarding': False,
                            'ipv6': True,
                            'native_apps': True,
                            'routes': [],
                            'type': 'host'})

                self.assertEqual(net.host_by_name['h1'].hostname, 'h1')
                self.assertEqual(net.host_by_name['h1'].terminal, True)
                self.assertEqual(net.host_by_name['h1'].prog, None)
                self.assertEqual(net.host_by_name['h1'].prog_window, None)

                # Node with host attributes that override default attributes
                cfg = io.StringIO('NODES\nh1')
                net = VirtualNetwork.from_file(
                        cfg, ['none'], {}, tmpdir, False)
                self.assertEqual(net.host_by_name['h1']._host_config(),
                        {'hostname': 'h1',
                            'interfaces': {},
                            'ip_forwarding': False,
                            'ipv6': False,
                            'native_apps': True,
                            'routes': [],
                            'type': 'host'})

                self.assertEqual(net.host_by_name['h1'].hostname, 'h1')
                self.assertEqual(net.host_by_name['h1'].terminal, False)
                self.assertEqual(net.host_by_name['h1'].prog, None)
                self.assertEqual(net.host_by_name['h1'].prog_window, None)

                # Node that overrides default attributes
                cfg = io.StringIO('NODES\nh1 type=switch,' + \
                        'native_apps=false,terminal=false,' + \
                        'prog=echo|foo,prog_window=split,ipv6=false')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                self.assertEqual(net.host_by_name['h1']._host_config(),
                        {'hostname': 'h1',
                            'interfaces': {},
                            'ip_forwarding': False,
                            'ipv6': False,
                            'native_apps': False,
                            'routes': [],
                            'type': 'switch'})

                self.assertEqual(net.host_by_name['h1'].hostname, 'h1')
                self.assertEqual(net.host_by_name['h1'].terminal, False)
                self.assertEqual(net.host_by_name['h1'].prog, 'echo|foo')
                self.assertEqual(net.host_by_name['h1'].prog_window, 'split')

                # Default attributes for switch
                cfg = io.StringIO('NODES\nh1 type=switch')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                self.assertEqual(net.host_by_name['h1']._host_config(),
                        {'hostname': 'h1',
                            'interfaces': {},
                            'ip_forwarding': False,
                            'ipv6': False,
                            'native_apps': True,
                            'routes': [],
                            'type': 'switch'})

    def test_host_routes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with tempfile.NamedTemporaryFile('w+', prefix='cougarnet', \
                    delete=True) as cfg:

                # Test route processing
                cfg = io.StringIO('''NODES
h1 routes=0.0.0.0/0|s1|10.0.0.1;10.0.2.0/24|s1|;::/0|s1|2001:db8::1;2001:db8:f00d::/64|s1|
s1
LINKS
h1,10.0.0.2/24,2001:db8::2/64 s1''')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                net.process_routes()
                self.assertEqual(net.host_by_name['h1'].routes,
                        [("0.0.0.0/0", "h1-s1", "10.0.0.1"),
                            ("10.0.2.0/24", "h1-s1", None),
                            ("::/0", "h1-s1", "2001:db8::1"),
                            ("2001:db8:f00d::/64", "h1-s1", None)])

    def test_link_config_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with tempfile.NamedTemporaryFile('w+', prefix='cougarnet', \
                    delete=True) as cfg:

                # Invalid link format (only one host)
                cfg = io.StringIO('''NODES
h1
s1
LINKS
h1''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid host attribute format (should be foo=bar)
                cfg = io.StringIO('''NODES
h1
s1
LINKS
h1 s1 foo''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid link attribute (foo)
                cfg = io.StringIO('''NODES
h1
s1
LINKS
h1 s1 foo=bar''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid link - invalid host
                cfg = io.StringIO('''NODES
h1
LINKS
h1 h2''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Multiple MAC addresses
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,00:00:00:00:11:11,00:00:00:00:00:00 h2''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # No prefix length for IP address
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.1 h2''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid IPv4 prefix length
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.1/33 h2''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid IPv4 address
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.256/24 h2''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # IPv4 addresses in different subnets
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.1/24,10.0.1.1/24 h2''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid IPv6 prefix length
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,fd00::/129 h2''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid IPv6 address
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,fg00::/64 h2''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # IPv6 addresses in different subnets
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,fd00::/64,fd00:1::/64 h2''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Same IPv4 addresses on both interfaces
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.1/24 h2,10.0.0.1/24''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Different IPv4 subnets on interfaces
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.1/24 h2,10.0.1.1/24''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Same IPv6 addresses on both interfaces
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,fd00::/64 h2,fd00::/64''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Different IPv6 subnets on interfaces
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,fd00::/64 h2,fd00:1::/64''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Both trunk and VLAN specified
                cfg = io.StringIO('''NODES
s1 type=switch
s2 type=switch
LINKS
s1 s2 trunk=true,vlan=1''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Trunk specified with two routers
                cfg = io.StringIO('''NODES
r1 type=router
r2 type=router
LINKS
r1 r2 trunk=true''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Trunk specified with switch and host
                cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1 s1 trunk=true''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # VLAN specified with non-switch
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1 h2 vlan=1''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid VLAN value
                cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1 s1 vlan=a''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Switch interface with MAC address
                cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1 s1,00:00:00:aa:aa:aa''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Switch interface with IPv4 address
                cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1 s1,10.0.0.1/24''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)


    def test_link_attrs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with tempfile.NamedTemporaryFile('w+', prefix='cougarnet', \
                    delete=True) as cfg:

                # Link with default attributes
                cfg = io.StringIO('''NODES
h1
s1
LINKS
h1 s1''')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                intf1 = net.host_by_name['h1'].int_by_name['h1-s1']
                intf2 = net.host_by_name['s1'].int_by_name['s1-h1']
                self.assertEqual(intf1.as_dict(),
                        {   'mac_addr': None,
                            'ipv4_addrs': [],
                            'ipv6_addrs': [],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': None,
                            'trunk': None,
                        })
                self.assertEqual(intf2.as_dict(),
                        {   'mac_addr': None,
                            'ipv4_addrs': [],
                            'ipv6_addrs': [],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': None,
                            'trunk': None,
                        })

                # Link that overrides default attributes
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,00:00:00:00:00:00,10.0.0.1/24,fd00:1::1/64 h2,00:00:00:00:11:11,10.0.0.3/24,fd00:1::3/64 bw=10Mbps,delay=100ms,loss=10%,mtu=500''')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                intf1 = net.host_by_name['h1'].int_by_name['h1-h2']
                intf2 = net.host_by_name['h2'].int_by_name['h2-h1']
                self.assertEqual(intf1.as_dict(),
                        {   'mac_addr': '00:00:00:00:00:00',
                            'ipv4_addrs': ['10.0.0.1/24'],
                            'ipv6_addrs': ['fd00:1::1/64'],
                            'bw': '10Mbps',
                            'delay': '100ms',
                            'loss': '10%',
                            'mtu': '500',
                            'vlan': None,
                            'trunk': None,
                        })
                self.assertEqual(intf2.as_dict(),
                        {   'mac_addr': '00:00:00:00:11:11',
                            'ipv4_addrs': ['10.0.0.3/24'],
                            'ipv6_addrs': ['fd00:1::3/64'],
                            'bw': '10Mbps',
                            'delay': '100ms',
                            'loss': '10%',
                            'mtu': '500',
                            'vlan': None,
                            'trunk': None,
                        })

                # Interfaces with multiple IP addresses
                cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,00:00:00:00:00:00,10.0.0.1/24,10.0.0.2/24,fd00:1::1/64,fd00:1::2/64 h2,00:00:00:00:11:11,10.0.0.3/24,10.0.0.4/24,fd00:1::3/64,fd00:1::4/64''')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                intf1 = net.host_by_name['h1'].int_by_name['h1-h2']
                intf2 = net.host_by_name['h2'].int_by_name['h2-h1']
                self.assertEqual(intf1.as_dict(),
                        {   'mac_addr': '00:00:00:00:00:00',
                            'ipv4_addrs': ['10.0.0.1/24', '10.0.0.2/24'],
                            'ipv6_addrs': ['fd00:1::1/64', 'fd00:1::2/64'],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': None,
                            'trunk': None,
                        })
                self.assertEqual(intf2.as_dict(),
                        {   'mac_addr': '00:00:00:00:11:11',
                            'ipv4_addrs': ['10.0.0.3/24', '10.0.0.4/24'],
                            'ipv6_addrs': ['fd00:1::3/64', 'fd00:1::4/64'],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': None,
                            'trunk': None,
                        })

                # Link with default attributes - switch and host
                cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1,00:00:00:00:00:00,10.0.0.1/24,fd00:1::1/64 s1''')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                intf1 = net.host_by_name['h1'].int_by_name['h1-s1']
                intf2 = net.host_by_name['s1'].int_by_name['s1-h1']
                self.assertEqual(intf1.as_dict(),
                        {   'mac_addr': '00:00:00:00:00:00',
                            'ipv4_addrs': ['10.0.0.1/24'],
                            'ipv6_addrs': ['fd00:1::1/64'],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': None,
                            'trunk': None,
                        })
                self.assertEqual(intf2.as_dict(),
                        {   'mac_addr': None,
                            'ipv4_addrs': [],
                            'ipv6_addrs': [],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': None,
                            'trunk': None,
                        })

                # Link that overrides default attributes - switch and host
                cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1,00:00:00:00:00:00,10.0.0.1/24,fd00:1::1/64 s1 bw=10Mbps,delay=100ms,loss=10%,mtu=500,vlan=1''')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                intf1 = net.host_by_name['h1'].int_by_name['h1-s1']
                intf2 = net.host_by_name['s1'].int_by_name['s1-h1']
                self.assertEqual(intf1.as_dict(),
                        {   'mac_addr': '00:00:00:00:00:00',
                            'ipv4_addrs': ['10.0.0.1/24'],
                            'ipv6_addrs': ['fd00:1::1/64'],
                            'bw': '10Mbps',
                            'delay': '100ms',
                            'loss': '10%',
                            'mtu': '500',
                            'vlan': None,
                            'trunk': None,
                        })
                self.assertEqual(intf2.as_dict(),
                        {   'mac_addr': None,
                            'ipv4_addrs': [],
                            'ipv6_addrs': [],
                            'bw': '10Mbps',
                            'delay': '100ms',
                            'loss': '10%',
                            'mtu': '500',
                            'vlan': 1,
                            'trunk': False,
                        })

                # Link between two switches - VLAN
                cfg = io.StringIO('''NODES
s1 type=switch
s2 type=switch
LINKS
s1 s2 vlan=1''')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                intf1 = net.host_by_name['s1'].int_by_name['s1-s2']
                intf2 = net.host_by_name['s2'].int_by_name['s2-s1']
                self.assertEqual(intf1.as_dict(),
                        {   'mac_addr': None,
                            'ipv4_addrs': [],
                            'ipv6_addrs': [],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': 1,
                            'trunk': False,
                        })
                self.assertEqual(intf2.as_dict(),
                        {   'mac_addr': None,
                            'ipv4_addrs': [],
                            'ipv6_addrs': [],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': 1,
                            'trunk': False,
                        })


                # Link between two switches - trunk
                cfg = io.StringIO('''NODES
s1 type=switch
s2 type=switch
LINKS
s1 s2 trunk=true''')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                intf1 = net.host_by_name['s1'].int_by_name['s1-s2']
                intf2 = net.host_by_name['s2'].int_by_name['s2-s1']
                self.assertEqual(intf1.as_dict(),
                        {   'mac_addr': None,
                            'ipv4_addrs': [],
                            'ipv6_addrs': [],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': None,
                            'trunk': True,
                        })
                self.assertEqual(intf2.as_dict(),
                        {   'mac_addr': None,
                            'ipv4_addrs': [],
                            'ipv6_addrs': [],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': None,
                            'trunk': True,
                        })

                # Link between switch and router - trunk
                cfg = io.StringIO('''NODES
s1 type=switch
r1 type=router
LINKS
s1 r1 trunk=true''')
                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                intf1 = net.host_by_name['s1'].int_by_name['s1-r1']
                intf2 = net.host_by_name['r1'].int_by_name['r1-s1']
                self.assertEqual(intf1.as_dict(),
                        {   'mac_addr': None,
                            'ipv4_addrs': [],
                            'ipv6_addrs': [],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': None,
                            'trunk': True,
                        })
                self.assertEqual(intf2.as_dict(),
                        {   'mac_addr': None,
                            'ipv4_addrs': [],
                            'ipv6_addrs': [],
                            'bw': None,
                            'delay': None,
                            'loss': None,
                            'mtu': None,
                            'vlan': None,
                            'trunk': True,
                        })

    def test_vlan_config_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:

                # Invalid link format (no router peer specified)
                cfg = io.StringIO('''NODES
s1 type=switch
r1 type=router
LINKS
s1 r1 trunk=true
VLANS
100 r1
''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # No addresses specified
                cfg = io.StringIO('''NODES
s1 type=switch
r1 type=router
LINKS
s1 r1 trunk=true
VLANS
100 r1,s1
''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Multiple MAC addresses
                cfg = io.StringIO('''NODES
s1 type=switch
r1 type=router
LINKS
s1 r1 trunk=true
VLANS
100 r1,s1,00:00:00:00:11:11,00:00:00:00:aa:aa
''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid VLAN - invalid host
                cfg = io.StringIO('''NODES
s1 type=switch
r1 type=router
LINKS
s1 r1 trunk=true
VLANS
100 r2,s1,10.0.1.2/24
''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid VLAN - host not a router
                cfg = io.StringIO('''NODES
s1 type=switch
r1 type=router
LINKS
s1 r1 trunk=true
VLANS
100 s1,r1,10.0.1.2/24
''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid VLAN - invalid peer host
                cfg = io.StringIO('''NODES
s1 type=switch
r1 type=router
LINKS
s1 r1 trunk=true
VLANS
100 r1,s2,10.0.1.2/24
''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid VLAN - no link between host and peer
                cfg = io.StringIO('''NODES
h1
s1 type=switch
r1 type=router
LINKS
s1 r1 trunk=true
VLANS
100 r1,h1,10.0.1.2/24
''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)

                # Invalid VLAN - link between host and peer is not a trunk
                cfg = io.StringIO('''NODES
s1 type=switch
r1 type=router
LINKS
s1 r1
VLANS
100 r1,s1,10.0.1.2/24
''')
                self.assertRaises(ConfigurationError,
                        VirtualNetwork.from_file,
                        cfg, [], {}, tmpdir, True)


    def test_vlan_attrs(self):
        with tempfile.TemporaryDirectory() as tmpdir:

                # Valid VLAN
                cfg = io.StringIO('''NODES
s1 type=switch
r1 type=router
LINKS
s1 r1 trunk=true
VLANS
100 r1,s1,00:00:00:aa:aa:aa,10.0.1.2/24,fd00::1:2/64
''')

                net = VirtualNetwork.from_file(
                        cfg, [], {}, tmpdir, True)
                intf = net.host_by_name['r1'].int_by_vlan[100]
                self.assertEqual(intf.as_dict(),
                        {   'mac_addr': '00:00:00:aa:aa:aa',
                            'ipv4_addrs': ['10.0.1.2/24'],
                            'ipv6_addrs': ['fd00::1:2/64']
                        })


if __name__ == '__main__':
    unittest.main()
