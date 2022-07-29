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

import csv
import io
import os
import subprocess
import sys

from .manager import RawPktHelperManager

RUN_NETNS_DIR = '/run/netns/'
HOSTINIT_MODULE = "cougarnet.virtualnet.hostinit"

def _run_cmd(cmd):
    sys.stderr.write(str(cmd) + '\n')
    proc = subprocess.run(cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    output = proc.stdout.decode('utf-8')
    return f'{proc.returncode},{output}'

def _run_cmd_netns(cmd, pid):
    cmd = ['nsenter', '--target', pid, '--all'] + cmd
    return _run_cmd(cmd)

class SysCmdHelper:
    def __init__(self, uid, gid):
        self._uid = uid
        self._gid = gid

        self.links = {}
        # ns_exists contains the ns that exist in /run/netns/
        self.netns_exists = set()
        # ns_mounted contains the ns that have been mounted;
        # this is a superset of ns_exists
        self.netns_mounted = set()
        self.ovs_ports = {}
        self.netns_to_pid = {}
        self.pid_to_netns = {}

    def require_netns(func):
        def _func(self, pid, *args, **kwargs):
            if pid not in self.pid_to_netns:
                return '1,Not within a mounted namespace'
            return func(self, pid, *args, **kwargs)
        return _func

    def _run_cmd_netns_or_not(self, cmd, intf):
        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'

        if self.links[intf] is None:
            # execute in default namespace
            return _run_cmd(cmd)

        netns = self.links[intf]
        if netns in self.netns_to_pid:
            # execute using nsenter and pid
            return _run_cmd_netns(cmd, self.netns_to_pid[netns])

        # execute using ip netns exec
        return '1,No PID associated with namespace'

    def add_link_veth(self, intf1, intf2):
        cmd = ['ip', 'link', 'add', intf1, 'type', 'veth']
        if intf2:
            cmd += ['peer', intf2]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.links[intf1] = None
            if intf2 is not None:
                self.links[intf2] = None
        return val

    def add_link_vlan(self, phys_intf, vlan_intf, vlan):
        if phys_intf not in self.links:
            return f'1,Interface does not exist: {phys_intf}'

        cmd = ['ip', 'link', 'add', 'link', phys_intf, 'name',
                vlan_intf, 'type', 'vlan', 'id', vlan]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.links[vlan_intf] = None
        return val

    def add_link_bridge(self, intf):
        cmd = ['ip', 'link', 'add',
                intf, 'type', 'bridge',
                'stp_state', '0', 'vlan_filtering', '0']

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.links[intf] = None
        return val

    def set_link_master(self, intf, bridge_intf):
        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'
        if bridge_intf not in self.links:
            return f'1,Bridge does not exist: {bridge_intf}'

        cmd = ['ip', 'link', 'set', intf, 'master', bridge_intf]
        return _run_cmd(cmd)

    def set_link_up(self, intf):
        cmd = ['ip', 'link', 'set', intf, 'up']
        return self._run_cmd_netns_or_not(cmd, intf)

    def set_link_mac_addr(self, intf, addr):
        cmd = ['ip', 'link', 'set', intf, 'address', addr]
        return self._run_cmd_netns_or_not(cmd, intf)

    def set_link_mtu(self, intf, mtu):
        cmd = ['ip', 'link', 'set', intf, 'mtu', mtu]
        return self._run_cmd_netns_or_not(cmd, intf)

    def set_link_attrs(self, intf, *attrs):
        cmd = ['tc', 'qdisc', 'add', 'dev', intf, 'root', 'netem'] + \
                list(attrs)
        return self._run_cmd_netns_or_not(cmd, intf)

    def set_link_ip_addr(self, intf, addr):
        if ':' in addr:
            cmd = ['ip', 'addr', 'add', addr, 'dev', intf]
        else:
            # set broadcast for IPv4 only
            cmd = ['ip', 'addr', 'add', addr, 'broadcast', '+', 'dev', intf]
        return self._run_cmd_netns_or_not(cmd, intf)

    @require_netns
    def set_lo_up(self, pid):
        cmd = [ 'ip', 'link', 'set', 'lo', 'up']
        return _run_cmd_netns(cmd, pid)

    def del_link(self, intf):
        cmd = ['ip', 'link', 'del', intf]

        val = self._run_cmd_netns_or_not(cmd, intf)
        if val.startswith('0,'):
            del self.links[intf]
        return val

    def add_netns(self, ns):
        nspath = os.path.join(RUN_NETNS_DIR, ns)

        val = '0,'
        if nspath not in self.netns_exists:
            if os.path.exists(nspath):
                return f'1,Namespace already exists: {nspath}'

            if not os.path.exists(RUN_NETNS_DIR):
                cmd = ['mkdir', '-p', RUN_NETNS_DIR]
                val = _run_cmd(cmd)
                if not val.startswith('0,'):
                    return val

            cmd = ['touch', nspath]
            val = _run_cmd(cmd)
            if not val.startswith('0,'):
                return val

        self.netns_exists.add(nspath)
        return val

    def umount_netns(self, ns):
        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if ns not in self.netns_mounted:
            return f'1,Namespace is not mounted: {nspath}'

        cmd = ['umount', nspath]
        val = val1 = None
        while True:
            # umount in a loop because sometimes it is mounted multiple times
            val1 = _run_cmd(cmd)
            if val is None:
                val = val1
            if not val1.startswith('0,'):
                break

        if val.startswith('0,'):
            self.netns_mounted.remove(ns)
        return val

    def del_netns(self, ns):
        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if nspath not in self.netns_exists:
            return f'1,Namespace does not exist: {nspath}'

        cmd = ['rm', nspath]
        val = _run_cmd(cmd)
        if not val.startswith('0,'):
            return val

        self.netns_exists.remove(nspath)
        return val

    def set_link_netns(self, intf, ns):
        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'
        if ns not in self.netns_mounted:
            return f'1,Namespace is not mounted: {nspath}'

        cmd = ['ip', 'link', 'set', intf, 'netns', ns]

        val = self._run_cmd_netns_or_not(cmd, intf)
        if val.startswith('0,'):
            self.links[intf] = ns
        return val

    def ovs_add_bridge(self, bridge):
        cmd = ['ovs-vsctl', 'add-br', bridge]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.ovs_ports[bridge] = set()
        return val

    def ovs_del_bridge(self, bridge):
        if bridge not in self.ovs_ports:
            return f'1,Bridge does not exist: {bridge}'

        cmd = ['ovs-vsctl', 'del-br', bridge]

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            del self.ovs_ports[bridge]
        return val

    def ovs_add_port(self, bridge, intf, vlan):
        if bridge not in self.ovs_ports:
            return f'1,Bridge does not exist: {bridge}'
        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'

        cmd = ['ovs-vsctl', 'add-port', bridge, intf]
        if vlan:
            cmd.append(f'tag={vlan}')

        val = _run_cmd(cmd)
        if val.startswith('0,'):
            self.ovs_ports[bridge].add(intf)
        return val

    def disable_ipv6(self, intf):
        cmd = ['sysctl', f'net/ipv6/conf/{intf}/disable_ipv6=1']
        return self._run_cmd_netns_or_not(cmd, intf)

    @require_netns
    def disable_lo_ipv6(self, pid):
        cmd = ['sysctl', f'net/ipv6/conf/lo/disable_ipv6=1']
        return _run_cmd_netns(cmd, pid)

    def disable_arp(self, intf):
        cmd = ['ip', 'link', 'set', intf, 'arp', 'off']
        return self._run_cmd_netns_or_not(cmd, intf)

    def disable_router_solicitations(self, intf):
        cmd = ['sysctl', f'net/ipv6/conf/{intf}/router_solicitations=0']
        return self._run_cmd_netns_or_not(cmd, intf)

    def unshare_hostinit(self, hostname, net, hosts_file, mount_sys,
            config_file, sys_cmd_helper_sock_remote, sys_cmd_helper_sock_local,
            comm_sock_remote, comm_sock_local, script_file):

        nspath = os.path.join(RUN_NETNS_DIR, hostname)

        if net and nspath not in self.netns_exists:
            return f'1,Namespace does not exist: {nspath}'

        cmd = ['unshare', '--mount', '--uts',
                f'--setuid={self._uid}', f'--setgid={self._gid}']
        if net:
            cmd += [f'--net={nspath}']
        cmd += [sys.executable, '-m', HOSTINIT_MODULE,
                    '--hosts-file', hosts_file]
        if mount_sys:
            cmd += ['--mount-sys']
        cmd += [config_file,
                sys_cmd_helper_sock_remote, sys_cmd_helper_sock_local,
                comm_sock_remote, comm_sock_local,
                script_file]

        p = subprocess.Popen(cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL)
        pid = str(p.pid)

        self.netns_mounted.add(hostname)
        self.netns_to_pid[hostname] = pid
        self.pid_to_netns[pid] = hostname
        return '0,'

    def start_rawpkt_helper(self, ns, *ints):
        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if ns not in self.netns_mounted:
            return f'1,Namespace is not mounted: {nspath}'

        helper = RawPktHelperManager(ns, *ints)
        if helper.start():
            return '0,'
        return '1,Helper not started'

    @require_netns
    def set_hostname(self, pid, hostname):
        cmd = ['hostname', hostname]
        return _run_cmd_netns(cmd, pid)

    @require_netns
    def add_route(self, pid, prefix, intf, next_hop):
        cmd = ['ip', 'route', 'add', prefix]
        if next_hop:
            cmd += ['via', next_hop]
        cmd += ['dev', intf]
        return _run_cmd_netns(cmd, pid)

    @require_netns
    def set_iptables_drop(self, pid):
        cmd = ['iptables', '-t', 'filter', '-I', 'INPUT', '-j', 'DROP']
        return _run_cmd_netns(cmd, pid)

    @require_netns
    def set_ip6tables_drop(self, pid):
        cmd = ['ip6tables', '-t', 'filter', '-I', 'INPUT', '-j', 'DROP']
        return _run_cmd_netns(cmd, pid)

    @require_netns
    def enable_ip_forwarding(self, pid):
        cmd = ['sysctl', 'net.ipv4.ip_forward=1']
        return _run_cmd_netns(cmd, pid)

    @require_netns
    def enable_ip6_forwarding(self, pid):
        cmd = ['sysctl', 'net.ipv6.conf.all.forwarding=1']
        return _run_cmd_netns(cmd, pid)

    @require_netns
    def mount_sys(self, pid):
        cmd = ['mount', '-t', 'sysfs', '/sys', '/sys']
        return _run_cmd_netns(cmd, pid)

    @require_netns
    def mount_hosts(self, pid, hosts_file):
        cmd = ['mount', '-o', 'bind', hosts_file, '/etc/hosts']
        return _run_cmd_netns(cmd, pid)

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
            try:
                if not parts[0].startswith('_') and \
                        hasattr(self, parts[0]):
                    func = getattr(self, parts[0])
                    status = func(*parts[1:])
                else:
                    status = f'1,Invalid command: {parts[0]}'
            except Exception as e:
                status = f'1,Command error: {parts}: {str(e)}'
            try:
                sock.sendto(status.encode('utf-8'), peer)
            except ConnectionRefusedError:
                pass
