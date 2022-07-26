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

import argparse
import asyncio
import atexit
import os
import socket
import subprocess
import sys

RUN_NETNS_DIR='/run/netns/'

def _delete_softly(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

def _raise():
    raise KeyboardInterrupt()

class NetConfigHelper:
    def __init__(self):
        self.links = set()
        self.netns = set()
        self.ovs_ports = {}

    def add_link_veth(self, intf1, intf2):
        cmd = ['sudo', 'ip', 'link', 'add',
                intf1, 'type', 'veth']
        if intf2:
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
            # we have to pipe stdout, or the return status will be non-zero
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
        except subprocess.CalledProcessError:
            return False

        return True

    def handle_request(self, sock):
        while True:
            try:
                msg, peer = sock.recvfrom(4096)
            except BlockingIOError:
                return
            msg = msg.decode('utf-8')
            parts = msg.split('|')
            if parts[0] == 'add_link_veth':
                status = self.add_link_veth(*parts[1:])
            elif parts[0] == 'add_link_vlan':
                status = self.add_link_vlan(*parts[1:])
            elif parts[0] == 'add_link_bridge':
                status = self.add_link_bridge(*parts[1:])
            elif parts[0] == 'set_link_master':
                status = self.set_link_master(*parts[1:])
            elif parts[0] == 'set_link_up':
                status = self.set_link_up(*parts[1:])
            elif parts[0] == 'del_link':
                status = self.del_link(*parts[1:])
            elif parts[0] == 'touch_netns':
                status = self.touch_netns(*parts[1:])
            elif parts[0] == 'umount_netns':
                status = self.umount_netns(*parts[1:])
            elif parts[0] == 'del_netns':
                status = self.del_netns(*parts[1:])
            elif parts[0] == 'ovs_add_bridge':
                status = self.ovs_add_bridge(*parts[1:])
            elif parts[0] == 'ovs_del_bridge':
                status = self.ovs_del_bridge(*parts[1:])
            elif parts[0] == 'ovs_add_port':
                status = self.ovs_add_port(*parts[1:])
            elif parts[0] == 'disable_ipv6':
                status = self.disable_ipv6(*parts[1:])
            else:
                status = False

            if status:
                msg = '1'.encode('utf-8')
            else:
                msg = '0'.encode('utf-8')
            sock.sendto(msg, peer)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', '-u',
            action='store', type=str,
            help='User that should own the socket')
    parser.add_argument('socket',
            action='store', type=str,
            help='Socket path ')

    args = parser.parse_args(sys.argv[1:])

    loop = asyncio.get_event_loop()
    loop.add_reader(sys.stdin, _raise)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.bind(args.socket)
    except OSError as e:
        sys.stderr.write(f'Invalid path: {args.socket} ({str(e)})\n')
        sys.exit(1)
    atexit.register(_delete_softly, args.socket)
    subprocess.run(['chmod', '700', args.socket], check=True)
    if args.user is not None:
        subprocess.run(['chown', args.user, args.socket], check=True)

    sock.setblocking(False)

    helper = NetConfigHelper()
    loop.add_reader(sock, helper.handle_request, sock)

    sys.stdout.buffer.write(b'\x00')
    sys.stdout.close()

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()

if __name__ == '__main__':
    main()
