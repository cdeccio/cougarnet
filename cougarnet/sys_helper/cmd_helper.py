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

'''Functions and classes for running a set of canned commands that require
privileges.'''

import csv
import io
import logging
import os
import random
import subprocess
import sys

from pyroute2 import NetNS
from pyroute2.netlink.exceptions import NetlinkError

from .manager import RawPktHelperManager

RUN_NETNS_DIR = '/run/netns/'
HOSTINIT_MODULE = "cougarnet.virtualnet.hostinit"

logger = logging.getLogger(__name__)

class SysCmdHelper:
    '''A class for executing a set of canned commands that require
    privileges.'''

    def __init__(self, uid, gid, log_only):
        self._uid = uid
        self._gid = gid
        self._log_only = log_only

        self.links = {}
        # ns_exists contains the ns that exist in /run/netns/
        self.netns_exists = set()
        # ns_mounted contains the ns that have been mounted;
        # this is a superset of ns_exists
        self.netns_mounted = set()
        self.ovs_ports = {}
        self.netns_to_pid = {}
        self.pid_to_netns = {}
        self.netns_to_iproute = {}

    def require_netns(func):
        '''A decorator for ensuring that a method is called with a pid that has
        been created by this running process, so we're not messing with
        processes that we haven't created.'''

        def _func(self, pid, *args, **kwargs):
            if pid not in self.pid_to_netns:
                return '1,Not within a mounted namespace'
            return func(self, pid, *args, **kwargs)
        return _func

    def _run_cmd(self, cmd):
        '''Run the specified command.  Return a string with the return code
        followed by the combined stdout/stderr output.'''

        logger.debug(' '.join(cmd))

        if self._log_only:
            return f'0,'

        proc = subprocess.run(cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        output = proc.stdout.decode('utf-8')
        return f'{proc.returncode},{output}'

    def _run_cmd_netns(self, cmd, pid):
        '''Run a command in the same namespace as the process with the given
        pid.'''

        cmd = ['nsenter', '--target', pid, '--all'] + cmd
        return self._run_cmd(cmd)

    def _run_cmd_netns_or_not(self, cmd, intf):
        '''Run a command, either in a specific namespace, if the interface
        corresponds to one, or in the default namespace otherwise.  If the
        interface is not one that we have created, then return an error.
        Otherwise, return the result.'''

        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'

        if self.links[intf] is None:
            # execute in default namespace
            return self._run_cmd(cmd)

        netns = self.links[intf]
        if netns in self.netns_to_pid:
            # execute using nsenter and pid
            return self._run_cmd_netns(cmd, self.netns_to_pid[netns])

        return '1,No PID associated with namespace'

    def add_link_veth(self, intf1, intf2):
        '''Add one or two interaces of type veth (virtual interfaces) with the
        specified name(s).  If intf2 is not empty, then two interfaces are
        created; otherwise, only one is created. Return the result.'''

        cmd = ['ip', 'link', 'add', intf1, 'type', 'veth']
        if intf2:
            cmd += ['peer', intf2]

        val = self._run_cmd(cmd)
        if val.startswith('0,'):
            self.links[intf1] = None
            if intf2:
                self.links[intf2] = None
        return val

    def add_link_vlan(self, phys_intf, vlan_intf, vlan):
        '''Add an interface of type vlan with the specified physical interface,
        name, and VLAN ID. Return the result.'''

        if phys_intf not in self.links:
            return f'1,Interface does not exist: {phys_intf}'

        cmd = ['ip', 'link', 'add', 'link', phys_intf, 'name',
                vlan_intf, 'type', 'vlan', 'id', vlan]

        val = self._run_cmd(cmd)
        if val.startswith('0,'):
            self.links[vlan_intf] = None
        return val

    def add_link_bridge(self, intf):
        '''Add an interface of type bridge with the specified name, with STP
        disabled and no VLAN filtering.  Return the result.'''

        cmd = ['ip', 'link', 'add',
                intf, 'type', 'bridge',
                'stp_state', '0', 'vlan_filtering', '0']

        val = self._run_cmd(cmd)
        if val.startswith('0,'):
            self.links[intf] = None
        return val

    def set_link_master(self, intf, bridge_intf):
        '''Associate the given interface (intf) with a bridge (bridge_intf).
        Return the result.'''

        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'
        if bridge_intf not in self.links:
            return f'1,Bridge does not exist: {bridge_intf}'

        cmd = ['ip', 'link', 'set', intf, 'master', bridge_intf]
        return self._run_cmd(cmd)

    def set_link_up(self, intf):
        '''Bring up a given interface, and return the result.'''

        cmd = ['ip', 'link', 'set', intf, 'up']
        return self._run_cmd_netns_or_not(cmd, intf)

    def set_link_down(self, intf):
        '''Bring down a given interface, and return the result.'''

        cmd = ['ip', 'link', 'set', intf, 'down']
        return self._run_cmd_netns_or_not(cmd, intf)

    def set_link_mac_addr(self, intf, addr):
        '''Set the MAC address for a given interface, and return the result.'''

        cmd = ['ip', 'link', 'set', intf, 'address', addr]
        return self._run_cmd_netns_or_not(cmd, intf)

    def set_link_mtu(self, intf, mtu):
        '''Set the MTU for a given interface, and return the result.'''

        cmd = ['ip', 'link', 'set', intf, 'mtu', mtu]
        return self._run_cmd_netns_or_not(cmd, intf)

    def set_link_attrs(self, intf, *attrs):
        '''Set the given link attributes (delay, bandwidth, loss) for a given
        interface, and return the result.'''

        cmd = ['tc', 'qdisc', 'add', 'dev', intf, 'root', 'netem'] + \
                list(attrs)
        return self._run_cmd_netns_or_not(cmd, intf)

    def set_link_ip_addr(self, intf, addr):
        '''Associate an IP address with a given interface, and return the
        result.'''

        if ':' in addr:
            cmd = ['ip', 'addr', 'add', addr, 'dev', intf]
        else:
            # set broadcast for IPv4 only
            cmd = ['ip', 'addr', 'add', addr, 'broadcast', '+', 'dev', intf]
        return self._run_cmd_netns_or_not(cmd, intf)

    @require_netns
    def set_lo_up(self, pid):
        '''Bring up the lo interface in the namespace associated with pid, and
        return the result.'''

        cmd = [ 'ip', 'link', 'set', 'lo', 'up']
        return self._run_cmd_netns(cmd, pid)

    def del_link(self, intf):
        '''Delete the given interface, and return the result.'''

        cmd = ['ip', 'link', 'del', intf]

        val = self._run_cmd_netns_or_not(cmd, intf)
        if val.startswith('0,'):
            del self.links[intf]
        return val

    def add_netns(self, ns):
        '''Create the mountpoint for a named namespace, and return the
        result.'''

        nspath = os.path.join(RUN_NETNS_DIR, ns)

        val = '0,'
        if nspath not in self.netns_exists:
            if os.path.exists(nspath):
                return f'1,Namespace already exists: {nspath}'

            if not os.path.exists(RUN_NETNS_DIR):
                cmd = ['mkdir', '-p', RUN_NETNS_DIR]
                val = self._run_cmd(cmd)
                if not val.startswith('0,'):
                    return val

            cmd = ['touch', nspath]
            val = self._run_cmd(cmd)
            if not val.startswith('0,'):
                return val

        self.netns_exists.add(nspath)
        return val

    def umount_netns(self, ns):
        '''Unmount the specified mountpoint for a named namespace, and return
        the result.'''

        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if ns not in self.netns_mounted:
            return f'1,Namespace is not mounted: {nspath}'

        cmd = ['umount', nspath]
        val = val1 = None
        while True:
            # umount in a loop because sometimes it is mounted multiple times
            val1 = self._run_cmd(cmd)
            if val is None:
                val = val1
            if not val1.startswith('0,'):
                break
            # self_run_cmd() always returns success when
            # self._log_only is True
            if self._log_only:
                break

        if val.startswith('0,'):
            self.netns_mounted.remove(ns)
        return val

    def del_netns(self, ns):
        '''Delete the specified mountpoint for a named namespace, and return
        the result.'''

        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if nspath not in self.netns_exists:
            return f'1,Namespace does not exist: {nspath}'

        cmd = ['rm', nspath]
        val = self._run_cmd(cmd)
        if not val.startswith('0,'):
            return val

        self.netns_exists.remove(nspath)
        return val

    def set_link_netns(self, intf, ns):
        '''Move the specified interface into a given namespace (ns), and return
        the result.'''

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
        '''Create a bridge within Open vSwitch with the specified name, and
        return the result.'''

        cmd = ['ovs-vsctl', 'add-br', bridge]

        val = self._run_cmd(cmd)
        if val.startswith('0,'):
            self.ovs_ports[bridge] = set()
        return val

    def ovs_del_bridge(self, bridge):
        '''Delete the bridge within Open vSwitch with the specified name, and
        return the result.'''

        if bridge not in self.ovs_ports:
            return f'1,Bridge does not exist: {bridge}'

        cmd = ['ovs-vsctl', 'del-br', bridge]

        val = self._run_cmd(cmd)
        if val.startswith('0,'):
            del self.ovs_ports[bridge]
        return val

    def ovs_flush_bridge(self, bridge):
        '''Flush the forwarding tables of the bridge with the specified name,
        and return the result.'''

        if bridge not in self.ovs_ports:
            return f'1,Bridge does not exist: {bridge}'

        cmd = ['ovs-appctl', 'fdb/flush', bridge]

        return self._run_cmd(cmd)

    def ovs_add_port(self, bridge, intf, vlan):
        '''Add a port with the given name to the existing bridge.  If vlan is
        not blank, then associate the port with that VLAN.  Otherwise,
        associate it with VLAN 0.  Return the result.'''

        if bridge not in self.ovs_ports:
            return f'1,Bridge does not exist: {bridge}'
        if intf not in self.links:
            return f'1,Interface does not exist: {intf}'

        cmd = ['ovs-vsctl', 'add-port', bridge, intf]
        if vlan:
            cmd.append(f'tag={vlan}')

        val = self._run_cmd(cmd)
        if val.startswith('0,'):
            self.ovs_ports[bridge].add(intf)
        return val

    def disable_ipv6(self, intf):
        '''Disable IPv6 on a given interface, and return the result.'''

        cmd = ['sysctl', f'net/ipv6/conf/{intf}/disable_ipv6=1']
        return self._run_cmd_netns_or_not(cmd, intf)

    @require_netns
    def disable_lo_ipv6(self, pid):
        '''Disable IPv6 on the lo interface in the namespace associated with
        pid, and return the result.'''

        cmd = ['sysctl', 'net/ipv6/conf/lo/disable_ipv6=1']
        return self._run_cmd_netns(cmd, pid)

    def disable_arp(self, intf):
        '''Disable ARP on a given interface, and return the result.'''

        cmd = ['ip', 'link', 'set', intf, 'arp', 'off']
        return self._run_cmd_netns_or_not(cmd, intf)

    def disable_router_solicitations(self, intf):
        '''Disable router solicitations on a given interface, and return the
        result.'''

        cmd = ['sysctl', f'net/ipv6/conf/{intf}/router_solicitations=0']
        return self._run_cmd_netns_or_not(cmd, intf)

    def unshare_hostinit(self, hostname, net, hosts_file, mount_sys,
            config_file, sys_cmd_helper_sock_remote, sys_cmd_helper_sock_local,
            comm_sock_remote, comm_sock_local, script_file):
        '''Run the hostinit module in a namespace that we have created, and
        return the result.'''

        nspath = os.path.join(RUN_NETNS_DIR, hostname)

        if net and nspath not in self.netns_exists:
            return f'1,Namespace does not exist: {nspath}'

        cmd = ['unshare', '--mount', '--uts', f'--setuid={self._uid}']
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

        logger.debug(' '.join(cmd))
        if self._log_only:
            #XXX This is probably better implemented with a variable that gets
            # incremented
            pid = str(random.randint(0, 1000000))
        else:
            p = subprocess.Popen(cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL)
            pid = str(p.pid)

        self.netns_mounted.add(hostname)
        self.netns_to_pid[hostname] = pid
        self.pid_to_netns[pid] = hostname
        return '0,'

    def start_rawpkt_helper(self, ns, *ints):
        '''Launch a process for passing packets from raw sockets to UNIX domain
        sockets and vice-versa using the RawPktHelperManager. Return the
        result.'''

        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if ns not in self.netns_mounted:
            return f'1,Namespace is not mounted: {nspath}'
        if ns not in self.netns_to_pid:
            return '1,No PID associated with namespace'

        helper = RawPktHelperManager(self.netns_to_pid[ns], *ints)
        if helper.start():
            return '0,'
        return '1,Helper not started'

    @require_netns
    def set_hostname(self, pid, hostname):
        '''Set the hostname within the namespace associated with a given
        pid.'''

        cmd = ['hostname', hostname]
        return self._run_cmd_netns(cmd, pid)

    @require_netns
    def add_route(self, pid, prefix, intf, next_hop):
        '''Add a route within the namespace associated with a given pid.'''

        cmd = ['ip', 'route', 'add', prefix]
        if next_hop:
            cmd += ['via', next_hop]
        cmd += ['dev', intf]

        logger.debug(' '.join(cmd))

        netns = self.pid_to_netns[pid]
        if netns not in self.netns_to_iproute:
             self.netns_to_iproute[netns] = NetNS(netns)
        ns = self.netns_to_iproute[netns]

        kwargs = { 'dst': prefix }
        if next_hop:
            kwargs['gateway'] = next_hop
        if intf:
            try:
                idx = ns.link_lookup(ifname=intf)[0]
            except IndexError:
                return f'1,Invalid interface: {intf}'
            kwargs['oif'] = idx

        try:
            ns.route('add', **kwargs)
        except (NetlinkError, OSError, struct.error) as e:
            return f'1,{str(e)}'
        finally:
            ns.close()
        return '0,'

    @require_netns
    def set_iptables_drop(self, pid, intf):
        '''Set an iptables rule to drop all incoming packets within the
        namespace associated with a given pid.'''

        cmd = ['iptables', '-t', 'filter', '-I', 'INPUT']
        if intf:
            cmd += ['-i', intf]
        cmd += ['-j', 'DROP']
        return self._run_cmd_netns(cmd, pid)

    @require_netns
    def set_ip6tables_drop(self, pid, intf):
        '''Set an ip6tables rule to drop all incoming packets within the
        namespace associated with a given pid.'''

        cmd = ['ip6tables', '-t', 'filter', '-I', 'INPUT']
        if intf:
            cmd += ['-i', intf]
        cmd += ['-j', 'DROP']
        return self._run_cmd_netns(cmd, pid)

    @require_netns
    def enable_ip_forwarding(self, pid):
        '''Enable IPv4 forwarding within the namespace associated with a given
        pid.'''

        cmd = ['sysctl', 'net.ipv4.ip_forward=1']
        return self._run_cmd_netns(cmd, pid)

    @require_netns
    def enable_ip6_forwarding(self, pid):
        '''Enable IPv6 forwarding within the namespace associated with a given
        pid.'''

        cmd = ['sysctl', 'net.ipv6.conf.all.forwarding=1']
        return self._run_cmd_netns(cmd, pid)

    @require_netns
    def mount_sys(self, pid):
        '''Mount the /sys filesystem within the namespace associated with a
        given pid.'''

        cmd = ['mount', '-t', 'sysfs', '/sys', '/sys']
        return self._run_cmd_netns(cmd, pid)

    @require_netns
    def mount_hosts(self, pid, hosts_file):
        '''Mount /etc/hosts onto the specified file within the namespace
        associated with a given pid.'''

        cmd = ['mount', '-o', 'bind', hosts_file, '/etc/hosts']
        return self._run_cmd_netns(cmd, pid)

    def handle_request(self, sock):
        '''Receive one or more requests from a given socket, and handle each.
        The command and its arguments are received a comma-separated list of
        items and converted into an actual list.  The method to call is the one
        corresponding to the command name received.  Return the result of
        calling the command to the client over the socket.'''

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
