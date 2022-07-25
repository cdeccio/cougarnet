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

import os
import subprocess

RUN_NETNS_DIR='/run/netns/'

class NetConfigHelper:
    def __init__(self):
        self.links = set()
        self.netns = set()
        self.ovs_ports = {}

    def add_link_veth(self, intf1, intf2):
        cmd = ['sudo', 'ip', 'link', 'add',
                intf1, 'type', 'veth']
        if intf2 is not None:
            cmd += ['peer', intf2]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        self.links.add(intf1)
        if intf2 is not None:
            self.links.add(intf2)

        return True

    def add_link_vlan(self, phys_intf, vlan_intf, vlan):
        if phys_intf not in self.links:
            return False

        cmd = ['sudo', 'ip', 'link', 'add', 'link',
                phys_intf, 'name', vlan_intf, 'type',
                'vlan', 'id', vlan]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        self.links.add(vlan_intf)

        return True

    def add_link_bridge(self, intf):
        cmd = ['sudo', 'ip', 'link', 'add',
                intf, 'type', 'bridge',
                'stp_state', '0', 'vlan_filtering', '0']

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        self.links.add(intf)

        return True

    def set_link_master(self, intf, bridge_intf):
        if intf not in self.links or \
                bridge_intf not in self.links:
            return False

        cmd = ['sudo', 'ip', 'link', 'set',
                intf, 'master', bridge_intf]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        return True

    def set_link_up(self, intf):
        if intf not in self.links:
            return False

        cmd = ['sudo', 'ip', 'link', 'set',
                intf, 'up']

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        return True

    def del_link(self, intf):
        if intf not in self.links:
            return False

        cmd = ['sudo', 'ip', 'link', 'del', intf]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        self.links.remove(intf)

        return True

    def touch_netns(self, ns):
        path = os.path.join(RUN_NETNS_DIR, ns)   
        
        if os.path.exists(path) and \
                path not in self.netns:
            return False

        cmd = ['sudo', 'touch', path]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        self.netns.add(path)

        return True

    def umount_netns(self, ns):
        path = os.path.join(RUN_NETNS_DIR, ns)   
        
        if path not in self.netns:
            return False

        cmd = ['sudo', 'umount', path]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        return True

    def del_netns(self, ns):
        path = os.path.join(RUN_NETNS_DIR, ns)   
        
        if path not in self.netns:
            return False

        cmd = ['sudo', 'rm', path]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        self.netns.remove(path)

        return True

    def ovs_add_bridge(self, bridge):
        cmd = ['sudo', 'ovs-vsctl', 'add-br', bridge]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        self.ovs_ports[bridge] = set()

        return True

    def ovs_del_bridge(self, bridge):
        if bridge not in self.ovs_ports:
            return False

        cmd = ['sudo', 'ovs-vsctl', 'del-br', bridge]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        del self.ovs_ports[bridge]

        return True

    def ovs_add_port(self, bridge, intf, vlan=None):
        if bridge not in self.ovs_ports:
            return False
        if intf not in self.links:
            return False

        cmd = ['sudo', 'ovs-vsctl', 'add-port',
                bridge, intf]
        if vlan is not None:
            cmd.append(f'tag={vlan}')

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        self.ovs_ports[bridge].add(intf)

        return True

    def disable_ipv6(self, intf):
        if intf not in self.links:
            return False

        cmd = ['sudo', 'sysctl', f'net/ipv6/conf/{intf}/disable_ipv6=1']

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            return False

        return True

def main():
    pass

if __name__ == '__main__':
    main()
