import io
import tempfile
import unittest

from cougarnet.virtualnet.manager import ConfigurationError
from cougarnet.virtualnet.manager import VirtualNetwork

class TestVirtualNetwork(VirtualNetwork):
    def _start_sys_cmd_helper(self):
        pass

class BadConfigTestCase(unittest.TestCase):
    def test_host_config_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid hostname
            cfg = io.StringIO('NODES\n1h')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid host attribute format (should be foo=bar)
            cfg = io.StringIO('NODES\nh1 foo')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid host attribute (foo)
            cfg = io.StringIO('NODES\nh1 foo=bar')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)

    def test_host_attrs(self):
        with tempfile.TemporaryDirectory() as tmpdir:

            # Node with default attributes
            cfg = io.StringIO('NODES\nh1')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
            self.assertEqual(net.host_by_name['h1']._host_config(),
                    {'hostname': 'h1',
                        'int_to_sock': {},
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


        with tempfile.TemporaryDirectory() as tmpdir:

            # Node with host attributes that override default attributes
            cfg = io.StringIO('NODES\nh1')
            net = TestVirtualNetwork.from_file(
                    cfg, ['none'], {}, tmpdir, False, True)
            self.assertEqual(net.host_by_name['h1']._host_config(),
                    {'hostname': 'h1',
                        'int_to_sock': {},
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


        with tempfile.TemporaryDirectory() as tmpdir:

            # Node that overrides default attributes
            cfg = io.StringIO('NODES\nh1 type=switch,' + \
                    'native_apps=false,terminal=false,' + \
                    'prog=echo|foo,prog_window=split,ipv6=false')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
            self.assertEqual(net.host_by_name['h1']._host_config(),
                    {'hostname': 'h1',
                        'int_to_sock': {},
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


        with tempfile.TemporaryDirectory() as tmpdir:

            # Default attributes for switch
            cfg = io.StringIO('NODES\nh1 type=switch')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
            self.assertEqual(net.host_by_name['h1']._host_config(),
                    {'hostname': 'h1',
                        'int_to_sock': {},
                        'interfaces': {},
                        'ip_forwarding': False,
                        'ipv6': False,
                        'native_apps': True,
                        'routes': [],
                        'type': 'switch'})


    def test_host_routes(self):

        with tempfile.TemporaryDirectory() as tmpdir:

            # Test route processing
            cfg = io.StringIO('''NODES
h1 routes=0.0.0.0/0|s1|10.0.0.1;10.0.2.0/24|s1|;::/0|s1|2001:db8::1;2001:db8:f00d::/64|s1|
s1
LINKS
h1,10.0.0.2/24,2001:db8::2/64 s1''')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
            net.process_routes()
            self.assertEqual(net.host_by_name['h1'].routes,
                    [("0.0.0.0/0", "h1-s1", "10.0.0.1"),
                        ("10.0.2.0/24", "h1-s1", None),
                        ("::/0", "h1-s1", "2001:db8::1"),
                        ("2001:db8:f00d::/64", "h1-s1", None)])

    def test_link_config_errors(self):

        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid link format (only one host)
            cfg = io.StringIO('''NODES
h1
s1
LINKS
h1''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid host attribute format (should be foo=bar)
            cfg = io.StringIO('''NODES
h1
s1
LINKS
h1 s1 foo''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid link attribute (foo)
            cfg = io.StringIO('''NODES
h1
s1
LINKS
h1 s1 foo=bar''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid link - invalid host
            cfg = io.StringIO('''NODES
h1
LINKS
h1 h2''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Multiple MAC addresses
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,00:00:00:00:11:11,00:00:00:00:00:00 h2''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # No prefix length for IP address
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.1 h2''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid IPv4 prefix length
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.1/33 h2''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid IPv4 address
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.256/24 h2''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # IPv4 addresses in different subnets
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.1/24,10.0.1.1/24 h2''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid IPv6 prefix length
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,fd00::/129 h2''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid IPv6 address
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,fg00::/64 h2''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # IPv6 addresses in different subnets
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,fd00::/64,fd00:1::/64 h2''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Same IPv4 addresses on both interfaces
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.1/24 h2,10.0.0.1/24''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Different IPv4 subnets on interfaces
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,10.0.0.1/24 h2,10.0.1.1/24''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Same IPv6 addresses on both interfaces
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,fd00::/64 h2,fd00::/64''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Different IPv6 subnets on interfaces
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,fd00::/64 h2,fd00:1::/64''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Both trunk and VLAN specified
            cfg = io.StringIO('''NODES
s1 type=switch
s2 type=switch
LINKS
s1 s2 trunk=true,vlan=1''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Trunk specified with two routers
            cfg = io.StringIO('''NODES
r1 type=router
r2 type=router
LINKS
r1 r2 trunk=true''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Trunk specified with switch and host
            cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1 s1 trunk=true''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # VLAN specified with non-switch
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1 h2 vlan=1''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Invalid VLAN value
            cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1 s1 vlan=a''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Switch interface with MAC address
            cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1 s1,00:00:00:aa:aa:aa''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

            # Switch interface with IPv4 address
            cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1 s1,10.0.0.1/24''')
            self.assertRaises(ConfigurationError,
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


    def test_link_attrs(self):

        with tempfile.TemporaryDirectory() as tmpdir:

            # Link with default attributes
            cfg = io.StringIO('''NODES
h1
s1
LINKS
h1 s1''')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
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


        with tempfile.TemporaryDirectory() as tmpdir:

            # Link that overrides default attributes
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,00:00:00:00:00:00,10.0.0.1/24,fd00:1::1/64 h2,00:00:00:00:11:11,10.0.0.3/24,fd00:1::3/64 bw=10Mbps,delay=100ms,loss=10%,mtu=500''')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
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


        with tempfile.TemporaryDirectory() as tmpdir:

            # Interfaces with multiple IP addresses
            cfg = io.StringIO('''NODES
h1
h2
LINKS
h1,00:00:00:00:00:00,10.0.0.1/24,10.0.0.2/24,fd00:1::1/64,fd00:1::2/64 h2,00:00:00:00:11:11,10.0.0.3/24,10.0.0.4/24,fd00:1::3/64,fd00:1::4/64''')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
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


        with tempfile.TemporaryDirectory() as tmpdir:

            # Link with default attributes - switch and host
            cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1,00:00:00:00:00:00,10.0.0.1/24,fd00:1::1/64 s1''')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
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


        with tempfile.TemporaryDirectory() as tmpdir:

            # Link that overrides default attributes - switch and host
            cfg = io.StringIO('''NODES
h1
s1 type=switch
LINKS
h1,00:00:00:00:00:00,10.0.0.1/24,fd00:1::1/64 s1 bw=10Mbps,delay=100ms,loss=10%,mtu=500,vlan=1''')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
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


        with tempfile.TemporaryDirectory() as tmpdir:

            # Link between two switches - VLAN
            cfg = io.StringIO('''NODES
s1 type=switch
s2 type=switch
LINKS
s1 s2 vlan=1''')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
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


        with tempfile.TemporaryDirectory() as tmpdir:

            # Link between two switches - trunk
            cfg = io.StringIO('''NODES
s1 type=switch
s2 type=switch
LINKS
s1 s2 trunk=true''')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
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


        with tempfile.TemporaryDirectory() as tmpdir:

            # Link between switch and router - trunk
            cfg = io.StringIO('''NODES
s1 type=switch
r1 type=router
LINKS
s1 r1 trunk=true''')
            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
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
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

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
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

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
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

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
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

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
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

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
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

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
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


        with tempfile.TemporaryDirectory() as tmpdir:

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
                    TestVirtualNetwork.from_file,
                    cfg, [], {}, tmpdir, True, True)


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

            net = TestVirtualNetwork.from_file(
                    cfg, [], {}, tmpdir, True, True)
            intf = net.host_by_name['r1'].int_by_vlan[100]
            self.assertEqual(intf.as_dict(),
                    {   'mac_addr': '00:00:00:aa:aa:aa',
                        'ipv4_addrs': ['10.0.1.2/24'],
                        'ipv6_addrs': ['fd00::1:2/64']
                    })


if __name__ == '__main__':
    unittest.main()
