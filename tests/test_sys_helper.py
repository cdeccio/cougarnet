import os
import subprocess
import tempfile
import unittest

from cougarnet.virtualnet.sys_helper import NetConfigHelper

class NetConfigTestCase(unittest.TestCase):
    def test_interfaces(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()

        try:
            subprocess.run(['ip', 'link', 'add', 'cn-foo', 'type', 'veth'])

            helper = NetConfigHelper()

            # interface doesn't exist
            self.assertEqual(
                    helper.add_link_vlan('cn-foo', 'cn-foo.vlan100', '100'),
                    False)
            self.assertEqual(
                    helper.set_link_master('cn-foo', 'cn-br'),
                    False)
            self.assertEqual(
                    helper.set_link_up('cn-foo'),
                    False)
            self.assertEqual(
                    helper.del_link('cn-foo'),
                    False)

            # add interfaces
            self.assertEqual(
                    helper.add_link_veth('cn-bar', None),
                    True)
            self.assertEqual(
                    helper.add_link_veth('cn-bar1', 'cn-bar2'),
                    True)
            self.assertEqual(
                    helper.add_link_vlan('cn-bar', 'cn-bar.vlan100', '100'),
                    True)
            self.assertEqual(
                    helper.links,
                    {'cn-bar1', 'cn-bar', 'cn-bar2', 'cn-bar.vlan100'})
            self.assertEqual(
                    helper.add_link_bridge('cn-br0'),
                    True)
            self.assertEqual(
                    helper.links,
                    {'cn-bar1', 'cn-br0', 'cn-bar2', 'cn-bar.vlan100', 'cn-bar'})

            # interface doesn't exist
            self.assertEqual(
                    helper.set_link_master('cn-bar1', 'cn-foo'),
                    False)
            # interface not a bridge
            self.assertEqual(
                    helper.set_link_master('cn-bar1', 'cn-bar2'),
                    False)
            # this should work
            self.assertEqual(
                    helper.set_link_master('cn-bar1', 'cn-br0'),
                    True)

            # this should work
            self.assertEqual(
                    helper.set_link_up('cn-bar1'),
                    True)

            # this should work
            self.assertEqual(
                    helper.del_link('cn-bar1'),
                    True)

            self.assertEqual(
                    helper.links,
                    {'cn-br0', 'cn-bar2', 'cn-bar.vlan100', 'cn-bar'})

        finally:
            os.unlink(tmp.name)

            for intf in ['cn-foo', 'cn-bar', 'cn-bar1', 'cn-bar2',
                    'cn-bar.vlan100', 'cn-br0']:
                subprocess.run(['sudo', 'ip', 'link', 'del', intf],
                        check=False)

    def test_sysctl(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            subprocess.run(['ip', 'link', 'add', 'cn-foo', 'type', 'veth'])

            helper = NetConfigHelper()

            # interface doesn't exist
            self.assertEqual(
                    helper.disable_ipv6('cn-foo'),
                    False)

            # add interfaces
            self.assertEqual(
                    helper.add_link_veth('cn-bar', None),
                    True)

            # this should work
            self.assertEqual(
                    helper.disable_ipv6('cn-bar'),
                    True)

        finally:
            os.unlink(tmp.name)

            for intf in ['cn-foo', 'cn-bar']:
                subprocess.run(['sudo', 'ip', 'link', 'del', intf],
                        check=False)

    def test_ovs(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            subprocess.run(['ip', 'link', 'add', 'cn-foo', 'type', 'veth'])

            helper = NetConfigHelper()

            # add interfaces
            self.assertEqual(
                    helper.add_link_veth('cn-bar', None),
                    True)

            # add bridge
            self.assertEqual(
                    helper.ovs_add_bridge('cn-br0'),
                    True)
            self.assertEqual(
                    helper.ovs_ports,
                    {'cn-br0': set()})


            # interface doesn't exist
            self.assertEqual(
                    helper.ovs_add_port('cn-br0', 'cn-foo'),
                    False)

            # add port
            self.assertEqual(
                    helper.ovs_add_port('cn-br0', 'cn-bar'),
                    True)
            self.assertEqual(
                    helper.ovs_ports,
                    {'cn-br0': { 'cn-bar' }})

            # bridge doesn't exist
            self.assertEqual(
                    helper.ovs_del_bridge('cn-foo'),
                    False)
            # delete bridge
            self.assertEqual(
                    helper.ovs_del_bridge('cn-br0'),
                    True)
            self.assertEqual(
                    helper.ovs_ports,
                    {})

        finally:
            os.unlink(tmp.name)

            for intf in ['cn-foo', 'cn-bar']:
                subprocess.run(['sudo', 'ip', 'link', 'del', intf],
                        check=False)
            subprocess.run(['sudo', 'ovs-vsctl', 'del-br', 'cn-br0'],
                    check=False)

    def test_netns(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()

        try:
            helper = NetConfigHelper()

            subprocess.run(['touch', '/run/netns/cn-foo'])

            self.assertEqual(
                    helper.touch_netns('cn-foo'),
                    False)
            self.assertEqual(
                    helper.touch_netns('cn-bar'),
                    True)
            self.assertEqual(
                    helper.touch_netns('cn-bar'),
                    True)
            self.assertEqual(
                    helper.netns,
                    {'/run/netns/cn-bar'})

            subprocess.run(['touch', tmp.name])
            subprocess.run(['mount', '-o', 'bind',
                tmp.name, '/run/netns/cn-bar'], check=True)

            # netns doesn't exist
            self.assertEqual(
                    helper.umount_netns('cn-foo'),
                    False)
            self.assertEqual(
                    helper.del_netns('cn-foo'),
                    False)

            # unmount and delete netns
            self.assertEqual(
                    helper.umount_netns('cn-bar'),
                    True)
            self.assertEqual(
                    helper.del_netns('cn-bar'),
                    True)
            self.assertEqual(
                    helper.netns,
                    set())

        finally:
            subprocess.run(['sudo', 'umount',
                    '/run/netns/cn-bar'], check=False)
            for intf in ['cn-foo', 'cn-bar']:
                subprocess.run(['sudo', 'rm',
                        os.path.join('/run/netns/', intf)],
                        check=False)
            os.unlink(tmp.name)

if __name__ == '__main__':
    unittest.main()
