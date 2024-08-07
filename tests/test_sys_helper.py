import os
import subprocess
import sys
import tempfile
import unittest

from cougarnet.sys_helper.cmd_helper.cmd_helper import SysCmdHelper

class NetConfigTestCase(unittest.TestCase):
    def test_interfaces(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()

        try:
            subprocess.run(['ip', 'link', 'add', 'cn-foo', 'type', 'veth'])

            helper = SysCmdHelper(1000, 1000)

            # interface doesn't exist
            self.assertEqual(
                    helper.add_link_vlan('cn-foo', 'cn-foo.vlan100', '100')[:2],
                    '9,')
            self.assertEqual(
                    helper.set_link_master('cn-foo', 'cn-br')[:2],
                    '9,')
            self.assertEqual(
                    helper.set_link_up('cn-foo')[:2],
                    '9,')
            self.assertEqual(
                    helper.del_link('cn-foo')[:2],
                    '9,')

            # add interfaces
            self.assertEqual(
                    helper.add_link_veth('cn-bar', None)[:2],
                    '0,')
            self.assertEqual(
                    helper.add_link_veth('cn-bar1', 'cn-bar2')[:2],
                    '0,')
            self.assertEqual(
                    helper.add_link_vlan('cn-bar', 'cn-bar.vlan100', '100')[:2],
                    '0,')
            self.assertEqual(
                    helper.links,
                    {'cn-bar': None, 'cn-bar1': None,
                            'cn-bar2': None, 'cn-bar.vlan100': None})
            self.assertEqual(
                    helper.add_link_bridge('cn-br0')[:2],
                    '0,')
            self.assertEqual(
                    helper.links,
                    {'cn-bar': None, 'cn-bar1': None, 'cn-br0': None,
                            'cn-bar2': None, 'cn-bar.vlan100': None})

            # interface doesn't exist
            self.assertEqual(
                    helper.set_link_master('cn-bar1', 'cn-foo')[:2],
                    '9,')
            # interface not a bridge
            self.assertEqual(
                    helper.set_link_master('cn-bar1', 'cn-bar2')[:2],
                    '2,')
            # this should work
            self.assertEqual(
                    helper.set_link_master('cn-bar1', 'cn-br0')[:2],
                    '0,')

            # this should work
            self.assertEqual(
                    helper.set_link_up('cn-bar1')[:2],
                    '0,')

            # this should work
            self.assertEqual(
                    helper.del_link('cn-bar1')[:2],
                    '0,')

            self.assertEqual(
                    helper.links,
                    {'cn-bar': None, 'cn-bar2': None,
                        'cn-bar.vlan100': None, 'cn-br0': None})

        finally:
            os.unlink(tmp.name)

            for intf in ['cn-foo', 'cn-bar', 'cn-bar1', 'cn-bar2',
                    'cn-bar.vlan100', 'cn-br0']:
                subprocess.run(['ip', 'link', 'del', intf],
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                        check=False)

    def test_sysctl(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            subprocess.run(['ip', 'link', 'add', 'cn-foo', 'type', 'veth'])

            helper = SysCmdHelper(1000, 1000)

            # interface doesn't exist
            self.assertEqual(
                    helper.disable_ipv6('cn-foo')[:2],
                    '9,')

            # add interfaces
            self.assertEqual(
                    helper.add_link_veth('cn-bar', None)[:2],
                    '0,')

            # this should work
            self.assertEqual(
                    helper.disable_ipv6('cn-bar')[:2],
                    '0,')

        finally:
            os.unlink(tmp.name)

            for intf in ['cn-foo', 'cn-bar']:
                subprocess.run(['ip', 'link', 'del', intf],
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                        check=False)

    def test_ovs(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            subprocess.run(['ip', 'link', 'add', 'cn-foo', 'type', 'veth'])

            helper = SysCmdHelper(1000, 1000)

            # add interfaces
            self.assertEqual(
                    helper.add_link_veth('cn-bar', None)[:2],
                    '0,')

            # add bridge
            self.assertEqual(
                    helper.ovs_add_bridge('cn-br0')[:2],
                    '0,')
            self.assertEqual(
                    helper.ovs_ports,
                    {'cn-br0': set()})

            # interface doesn't exist
            self.assertEqual(
                    helper.ovs_add_port('cn-br0', 'cn-foo', '')[:2],
                    '9,')

            # add port
            self.assertEqual(
                    helper.ovs_add_port('cn-br0', 'cn-bar', '')[:2],
                    '0,')
            self.assertEqual(
                    helper.ovs_ports,
                    {'cn-br0': { 'cn-bar' }})

            # bridge doesn't exist
            self.assertEqual(
                    helper.ovs_del_bridge('cn-foo')[:2],
                    '9,')
            # delete bridge
            self.assertEqual(
                    helper.ovs_del_bridge('cn-br0')[:2],
                    '0,')
            self.assertEqual(
                    helper.ovs_ports,
                    {})

        finally:
            os.unlink(tmp.name)

            for intf in ['cn-foo', 'cn-bar']:
                subprocess.run(['ip', 'link', 'del', intf],
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                        check=False)
            subprocess.run(['ovs-vsctl', 'del-br', 'cn-br0'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                    check=False)

    def test_netns(self):
        p = None

        try:
            helper = SysCmdHelper(1000, 1000)

            subprocess.run(['touch', '/run/netns/cn-foo'])

            self.assertEqual(
                    helper.add_netns('cn-foo')[:2],
                    '9,')
            self.assertEqual(
                    helper.add_netns('cn-bar')[:2],
                    '0,')
            self.assertEqual(
                    helper.add_netns('cn-bar')[:2],
                    '0,')
            self.assertEqual(
                    helper.netns_exists,
                    {'/run/netns/cn-bar'})

            p1 = subprocess.Popen(['unshare', '--uts',
                                   '--net=/run/netns/cn-bar',
                                   '/bin/sleep', '30'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

            p2 = subprocess.Popen(['/bin/sleep', '30'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

            # add interface
            self.assertEqual(
                    helper.add_link_veth('cn-baz', None)[:2],
                    '0,')

            # interface doesn't exist
            self.assertEqual(
                    helper.set_link_netns('cn-foo', 'cn-bar')[:2],
                    '9,')
            # netns doesn't exist
            self.assertEqual(
                    helper.set_link_netns('cn-baz', 'cn-foo')[:2],
                    '9,')

            output = subprocess.run(['ls', '/sys/class/net'],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE).stdout
            ints = output.decode('utf-8').splitlines()
            self.assertEqual('cn-baz' in ints, True)

            helper.netns_mounted.add('cn-bar')

            # this should work
            self.assertEqual(
                    helper.set_link_netns('cn-baz', 'cn-bar')[:2],
                    '0,')

            #output = subprocess.run(['ip', 'netns',
            #            'exec', 'cn-bar', 'ls', '/sys/class/net'],
            #    stdin=subprocess.DEVNULL,
            #    stdout=subprocess.PIPE).stdout
            #ints = output.decode('utf-8').splitlines()
            #self.assertEqual('cn-baz' in ints, False)

            # netns doesn't exist
            self.assertEqual(
                    helper.umount_netns('cn-foo')[:2],
                    '9,')
            self.assertEqual(
                    helper.del_netns('cn-foo')[:2],
                    '9,')

            # unmount and delete netns
            self.assertEqual(
                    helper.umount_netns('cn-bar')[:2],
                    '0,')
            self.assertEqual(
                    helper.del_netns('cn-bar')[:2],
                    '0,')
            self.assertEqual(
                    helper.netns_exists,
                    set())

            # process doesn't exist, so _get_ns_info() returns None
            self.assertIsNone(
                    helper._get_ns_info(0))

            # process exists, so _get_ns_info() returns a non-None value
            self.assertIsNotNone(
                    helper._get_ns_info(p1.pid))

            # namespace information for this process and some other process
            # started without unshare should be the same.
            self.assertEqual(
                    helper._get_ns_info(p2.pid),
                    helper._get_ns_info(os.getpid()))

            # namespace information for a process started without unshare and a
            # process started with unshare should be different.
            self.assertNotEqual(
                    helper._get_ns_info(p1.pid),
                    helper._get_ns_info(p2.pid))

            # Cannot retrieve namespace information for p2.pid with
            # store_ns_info() because the pid is not "registered".
            self.assertEqual(
                    helper.store_ns_info(str(p2.pid))[:2],
                    '9,')

            # Artificially populate the data structures as if
            # unshare_hostinit() and update_pid() had been called.
            helper.netns_mounted.add('cn-bar')
            helper.pid_to_netns[str(p2.pid)] = 'cn-bar'
            helper.netns_to_pid['cn-bar'] = str(p2.pid)

            # Test that the data structures have the expected values.
            self.assertEqual(
                    helper.netns_to_pid,
                    {'cn-bar': str(p2.pid)})
            self.assertEqual(
                    helper.pid_to_netns,
                    {str(p2.pid): 'cn-bar'})
            self.assertEqual(
                    list(helper.ns_info_cache.keys()),
                    [])

            # Now that p2.pid is "registered" (i.e., through the above calls),
            # call store_ns_info() again, and this time it should succeed.
            self.assertEqual(
                    helper.store_ns_info(str(p2.pid))[:2],
                    '0,')

            # At this point, ns_info_cache() should be populated.
            self.assertEqual(
                    list(helper.ns_info_cache.keys()),
                    [str(p2.pid)])

            # Updating the pid will not work because the old pid is invalid.
            self.assertEqual(
                    helper.update_pid(0, str(p2.pid))[:2],
                    '9,')

            # Updating the pid will not work because the new pid is invalid.
            self.assertEqual(
                    helper.update_pid(str(p2.pid), 0)[:2],
                    '9,')

            # Updating the pid will not work because the namespace of the new
            # pid does not match the namespace of the old pid.
            self.assertEqual(
                    helper.update_pid(str(p2.pid), str(p1.pid))[:2],
                    '9,')

            # Update the old pid with the new pid.  This time everything
            # matches, so it should work.
            self.assertEqual(
                    helper.update_pid(str(p2.pid), str(os.getpid()))[:2],
                    '0,')

            # Test that the data structures have the expected values, after
            # calling update_pid().  At this point, the new pid should have
            # replaced old pid.
            self.assertEqual(
                    helper.netns_to_pid,
                    { 'cn-bar': str(os.getpid()) })
            self.assertEqual(
                    helper.pid_to_netns,
                    { str(os.getpid()): 'cn-bar' })
            self.assertEqual(
                    list(helper.ns_info_cache.keys()),
                    [str(os.getpid())])

        finally:
            subprocess.run(['umount', '/run/netns/cn-bar'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                    check=False)
            for intf in ['cn-foo', 'cn-bar']:
                subprocess.run(['rm', os.path.join('/run/netns/', intf)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                        check=False)
            subprocess.run(['ip', 'link', 'del', 'cn-baz'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                    check=False)
            if p1 is not None:
                subprocess.run(['kill', str(p1.pid)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                    check=False)
            if p2 is not None:
                subprocess.run(['kill', str(p2.pid)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                    check=False)

if __name__ == '__main__':
    # make sure we are running as root
    if os.geteuid() != 0:
        sys.stderr.write('This program must be run as root.\n')
        sys.exit(1)
    unittest.main()
