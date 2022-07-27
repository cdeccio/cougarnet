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
import csv
import io
import os
import socket
import subprocess
import sys

RUN_NETNS_DIR='/run/netns/'

def _raise():
    raise KeyboardInterrupt()

def _run_cmd(cmd):
    proc = subprocess.run(cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    output = proc.stdout.decode('utf-8')
    return f'{proc.returncode},{output}'

class NetConfigHelper:
    def __init__(self):
        self.links = set()
        # ns_exists contains the ns that exist in /run/netns/
        self.netns_exists = set()
        # ns_mounted contains the ns that have been mounted;
        # this is a superset of ns_exists
        self.netns_mounted = set()
        self.ovs_ports = {}

    def require_netns(func):
        def _func(self, ns, *args, **kwargs):
            path = os.path.join(RUN_NETNS_DIR, ns)
            if path not in self.netns_exists:
                return False
            return func(self, ns, *args, **kwargs)
        return _func

    def add_link_veth(self, intf1, intf2):
        cmd = ['sudo', 'ip', 'link', 'add',
                intf1, 'type', 'veth']
        if intf2:
            cmd += ['peer', intf2]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.links.add(intf1)
            if intf2 is not None:
                self.links.add(intf2)
        return val

    def add_link_vlan(self, phys_intf, vlan_intf, vlan):
        if phys_intf not in self.links:
            return f'1,Interface does not exist: {phys_intf}'

        cmd = ['sudo', 'ip', 'link', 'add', 'link',
                phys_intf, 'name', vlan_intf, 'type',
                'vlan', 'id', vlan]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.links.add(vlan_intf)
        return val

    def add_link_bridge(self, intf):
        cmd = ['sudo', 'ip', 'link', 'add',
                intf, 'type', 'bridge',
                'stp_state', '0', 'vlan_filtering', '0']

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.links.add(intf)
        return val

    def set_link_master(self, intf, bridge_intf):
        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'
        if bridge_intf not in self.links:
            return f'1,Bridge does not exist: {bridge_intf}'

        cmd = ['sudo', 'ip', 'link', 'set',
                intf, 'master', bridge_intf]

        return _run_cmd(cmd)

    def set_link_up(self, intf):
        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'

        cmd = ['sudo', 'ip', 'link', 'set',
                intf, 'up']

        return _run_cmd(cmd)

    def del_link(self, intf):
        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'

        cmd = ['sudo', 'ip', 'link', 'del', intf]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.links.remove(intf)
        return val

    def add_netns(self, ns):
        path = os.path.join(RUN_NETNS_DIR, ns)

        if os.path.exists(path) and \
                path not in self.netns_exists:
            return f'1,Namespace does not exist: {path}'

        cmd = ['sudo', 'touch', path]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.netns_exists.add(path)
        return val

    def umount_netns(self, ns):
        path = os.path.join(RUN_NETNS_DIR, ns)

        if path not in self.netns_mounted:
            return f'1,Namespace is not mounted: {path}'

        cmd = ['sudo', 'umount', path]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.netns_mounted.remove(path)
        return val

    def del_netns(self, ns):
        path = os.path.join(RUN_NETNS_DIR, ns)

        if path not in self.netns_exists:
            return f'1,Namespace does not exist: {path}'

        cmd = ['sudo', 'rm', path]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            try:
                self.netns_mounted.remove(path)
            except KeyError:
                pass
            self.netns_exists.remove(path)
        return val

    def set_link_netns(self, intf, ns):
        path = os.path.join(RUN_NETNS_DIR, ns)

        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'
        if path not in self.netns_exists:
            return f'1,Namespace does not exist: {path}'

        cmd = ['sudo', 'ip', 'link', 'set',
                intf, 'netns', ns]

        return _run_cmd(cmd)

    def ovs_add_bridge(self, bridge):
        cmd = ['sudo', 'ovs-vsctl', 'add-br', bridge]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.ovs_ports[bridge] = set()
        return val

    def ovs_del_bridge(self, bridge):
        if bridge not in self.ovs_ports:
            return f'1,Bridge does not exist: {bridge}'

        cmd = ['sudo', 'ovs-vsctl', 'del-br', bridge]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            del self.ovs_ports[bridge]
        return val

    def ovs_add_port(self, bridge, intf, vlan=None):
        if bridge not in self.ovs_ports:
            return f'1,Bridge does not exist: {bridge}'
        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'

        cmd = ['sudo', 'ovs-vsctl', 'add-port',
                bridge, intf]
        if vlan is not None:
            cmd.append(f'tag={vlan}')

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.ovs_ports[bridge].add(intf)
        return val

    def disable_ipv6(self, intf):
        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'

        cmd = ['sudo', 'sysctl', f'net/ipv6/conf/{intf}/disable_ipv6=1']

        return _run_cmd(cmd)

    def handle_request(self, sock):
        while True:
            try:
                msg, peer = sock.recvfrom(4096)
            except BlockingIOError:
                return
            msg = msg.decode('utf-8')
            s = io.StringIO(msg)
            csv_reader = csv.reader(s)
            parts = next(csv_reader)
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
            elif parts[0] == 'add_netns':
                status = self.add_netns(*parts[1:])
            elif parts[0] == 'umount_netns':
                status = self.umount_netns(*parts[1:])
            elif parts[0] == 'del_netns':
                status = self.del_netns(*parts[1:])
            elif parts[0] == 'set_link_netns':
                status = self.set_link_netns(*parts[1:])
            elif parts[0] == 'ovs_add_bridge':
                status = self.ovs_add_bridge(*parts[1:])
            elif parts[0] == 'ovs_del_bridge':
                status = self.ovs_del_bridge(*parts[1:])
            elif parts[0] == 'ovs_add_port':
                status = self.ovs_add_port(*parts[1:])
            elif parts[0] == 'disable_ipv6':
                status = self.disable_ipv6(*parts[1:])
            else:
                status = '1,Invalid command'
            sock.sendto(status.encode('utf-8'), peer)

def _setup_socket(path, user):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.bind(path)
    except OSError as e:
        sys.stderr.write(f'Invalid path: {path} ({str(e)})\n')
        sys.exit(1)

    # delete the file on program exit
    atexit.register(os.unlink, path)

    # set permissions and ownership
    try:
        subprocess.run(['chmod', '700', path], check=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f'Changing socket permissions unsuccessful: ({str(e)})\n')
        sys.exit(1)
    try:
        subprocess.run(['chown', user, path], check=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f'Changing socket ownership unsuccessful: ({str(e)})\n')
        sys.exit(1)

    # set non-blocking, so it can be used with the listener
    sock.setblocking(False)
    return sock

def _send_byte_to_stdout():
    sys.stdout.buffer.write(b'\x00')
    sys.stdout.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('user',
            action='store', type=str,
            help='User that should own the socket')
    parser.add_argument('socket',
            action='store', type=str,
            help='Socket path ')

    args = parser.parse_args(sys.argv[1:])

    # make sure we are running as root
    if os.geteuid() != 0:
        sys.stderr.write('Please run this program as root.\n')
        sys.exit(1)

    helper = NetConfigHelper()
    loop = asyncio.get_event_loop()

    # exit as soon stdin is closed
    # (an indicator from our parent that we should terminate)
    loop.add_reader(sys.stdin, _raise)

    sock = _setup_socket(args.socket, args.user)

    # register the socket with the event loop
    loop.add_reader(sock, helper.handle_request, sock)

    # communicate to the parent that everything is set up
    _send_byte_to_stdout()

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()

if __name__ == '__main__':
    main()
