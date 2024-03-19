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

import logging
import os
import signal
import subprocess
import struct
import sys

from pyroute2 import NetNS, netns
from pyroute2.netlink.exceptions import NetlinkError

from cougarnet.sys_helper.rawpkt_helper.manager import \
        RawPktHelperManager
from cougarnet import util

PROC_NS_DIR = '/proc/%d/ns/'
RUN_NETNS_DIR = '/run/netns/'
FRR_CONF_DIR = '/etc/frr/'
FRR_RUN_DIR = '/var/run/frr/'
FRR_PROG_DIR = '/usr/lib/frr'
FRR_ZEBRA_PROG = os.path.join(FRR_PROG_DIR, 'zebra')
FRR_RIPD_PROG = os.path.join(FRR_PROG_DIR, 'ripd')
FRR_RIPNGD_PROG = os.path.join(FRR_PROG_DIR, 'ripngd')

FRR_ZEBRA_PID_FILE = 'zebra.pid'
FRR_RIPD_PID_FILE = 'ripd.pid'
FRR_RIPNGD_PID_FILE = 'ripngd.pid'
FRR_ZEBRA_CONF_FILE = 'zebra.conf'
FRR_RIPD_CONF_FILE = 'ripd.conf'
FRR_RIPNGD_CONF_FILE = 'ripngd.conf'
FRR_ZEBRA_VTY_FILE = 'zebra.vty'
FRR_RIPD_VTY_FILE = 'ripd.vty'
FRR_RIPNGD_VTY_FILE = 'ripngd.vty'
FRR_ZSERV_FILE = 'zserv.api'

HOSTINIT_MODULE = "cougarnet.virtualnet.hostinit"

logger = logging.getLogger(__name__)

class SysCmdHelper:
    '''A class for executing a set of canned commands that require
    privileges.'''

    def __init__(self, uid, gid, frr_uid=None, frr_gid=None):
        self._uid = uid
        self._gid = gid

        self._frr_uid = frr_uid
        self._frr_gid = frr_gid

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
        self.zebra_started = set()
        self.ripd_started = set()
        self.ripngd_started = set()

        self.ns_info_cache = {}

    def require_netns(func):
        '''A decorator for ensuring that a method is called with a pid that has
        been created by this running process, so we're not messing with
        processes that we haven't created.'''

        def _func(self, pid, *args, **kwargs):
            if pid not in self.pid_to_netns:
                return '9,,Not within a mounted namespace'
            return func(self, pid, *args, **kwargs)
        return _func

    def _run_cmd(self, cmd):
        '''Run the specified command.  Return a string with the return code
        followed by the combined stdout/stderr output.'''

        cmd_str = ' '.join(cmd)
        logger.debug(cmd_str)

        proc = subprocess.run(cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        output = proc.stdout.decode('utf-8')
        ret = [proc.returncode, cmd_str, output]

        return util.list_to_csv_str(ret)

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
            return f'9,,Interface does not exist: {intf}'

        if self.links[intf] is None:
            # execute in default namespace
            return self._run_cmd(cmd)

        netns1 = self.links[intf]
        if netns1 in self.netns_to_pid:
            # execute using nsenter and pid
            return self._run_cmd_netns(cmd, self.netns_to_pid[netns1])

        return '9,,No PID associated with namespace'

    @classmethod
    def _kill(cls, pid, sig):
        '''Call os.kill() to send a signal to a given process.'''

        cmd = ['kill', f'-{sig}', str(pid)]
        cmd_str = ' '.join(cmd)
        logger.debug(cmd_str)

        try:
            os.kill(pid, sig)
        except OSError as e:
            parts = ['1', cmd_str, str(e)]
            return util.list_to_csv_str(parts)

        return '0,'

    @classmethod
    def _mkdir(cls, path, mode=0o777):
        '''Call os.mkdir() to create a directory with the specified mode.'''

        cmd = ['mkdir', path]
        cmd_str = ' '.join(cmd)
        logger.debug(cmd_str)

        try:
            os.mkdir(path, mode=mode)
        except OSError as e:
            parts = ['1', cmd_str, str(e)]
            return util.list_to_csv_str(parts)

        return '0,'

    @classmethod
    def _unlink(cls, path):
        '''Call os.unlink() to remove a file.'''

        cmd = ['rm', path]
        cmd_str = ' '.join(cmd)
        logger.debug(cmd_str)

        try:
            os.unlink(path)
        except OSError as e:
            parts = ['1', cmd_str, str(e)]
            return util.list_to_csv_str(parts)

        return '0,'

    @classmethod
    def _rmdir(cls, path):
        '''Call os.rmdir() to remove a directory.'''

        cmd = ['rmdir', path]
        cmd_str = ' '.join(cmd)
        logger.debug(cmd_str)

        try:
            os.rmdir(path)
        except OSError as e:
            parts = ['1', cmd_str, str(e)]
            return util.list_to_csv_str(parts)

        return '0,'

    @classmethod
    def _chown(cls, path, uid, gid):
        '''Call os.chown() to change ownership on a file or directory.'''

        cmd = ['chown', f'{uid}:{gid}', path]
        cmd_str = ' '.join(cmd)
        logger.debug(cmd_str)

        try:
            os.chown(path, uid, gid)
        except OSError as e:
            parts = ['1', cmd_str, str(e)]
            return util.list_to_csv_str(parts)

        return '0,'

    @classmethod
    def _chmod(cls, path, mode):
        '''Call os.chmod() to change the mode of a file or directory.'''

        cmd = ['chmod', str(mode), path]
        cmd_str = ' '.join(cmd)
        logger.debug(cmd_str)

        try:
            os.chmod(path, mode)
        except OSError as e:
            parts = ['1', cmd_str, str(e)]
            return util.list_to_csv_str(parts)

        return '0,'

    @classmethod
    def _get_ns_info(cls, pid):
        '''Retrive the device and inode information associated with the
        namespaces for a given process.'''

        ns_info = {}
        nsdir = PROC_NS_DIR % pid
        try:
            for f in os.listdir(nsdir):
                path = os.path.join(nsdir, f)
                with open(path) as fh:
                    val = os.fstat(fh.fileno())
                    ns_info[f] = (os.major(val.st_dev), os.minor(val.st_dev), val.st_ino)
        except (FileNotFoundError, PermissionError) as e:
            return None

        return ns_info

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
            return f'9,,Interface does not exist: {phys_intf}'

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
                'stp_state', '0', 'vlan_filtering', '0',
                'ageing_time', '0']

        val = self._run_cmd(cmd)
        if val.startswith('0,'):
            self.links[intf] = None
        return val

    def set_link_master(self, intf, bridge_intf):
        '''Associate the given interface (intf) with a bridge (bridge_intf).
        Return the result.'''

        if intf not in self.links:
            return f'9,,Interface does not exist: {intf}'
        if bridge_intf not in self.links:
            return f'9,,Bridge does not exist: {bridge_intf}'

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
                return f'9,,Namespace already exists: {nspath}'

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
            return f'9,,Namespace is not mounted: {nspath}'

        cmd = ['umount', nspath]
        val = val1 = None
        while True:
            # umount in a loop because sometimes it is mounted multiple times
            val1 = self._run_cmd(cmd)
            if val is None:
                val = val1
            if not val1.startswith('0,'):
                break

        if val.startswith('0,'):
            self.netns_mounted.remove(ns)
        return val

    def del_netns(self, ns):
        '''Delete the specified mountpoint for a named namespace, and return
        the result.'''

        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if nspath not in self.netns_exists:
            return f'9,,Namespace does not exist: {nspath}'

        val = self._unlink(nspath)
        if not val.startswith('0,'):
            return val

        self.netns_exists.remove(nspath)
        return val

    def add_pid_for_netns(self, pid):
        '''Associate a new pid with an existing namespace.'''

        ns = netns.pid_to_ns(pid)
        if ns is None:
            return '9,,Process does not exist or ' + \
                    f'process not in any namespace: {pid}'
        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if nspath not in self.netns_exists:
            return f'9,,Namespace does not exist: {nspath}'

        if ns not in self.netns_to_pid:
            self.netns_to_pid[ns] = pid
        self.pid_to_netns[pid] = ns

        return '0,'

    def set_link_netns(self, intf, ns):
        '''Move the specified interface into a given namespace (ns), and return
        the result.'''

        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if intf not in self.links:
            return f'9,,Interface does not exist: {intf}'
        if ns not in self.netns_mounted:
            return f'9,,Namespace is not mounted: {nspath}'

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
            return f'9,,Bridge does not exist: {bridge}'

        cmd = ['ovs-vsctl', 'del-br', bridge]

        val = self._run_cmd(cmd)
        if val.startswith('0,'):
            del self.ovs_ports[bridge]
        return val

    def ovs_flush_bridge(self, bridge):
        '''Flush the forwarding tables of the bridge with the specified name,
        and return the result.'''

        if bridge not in self.ovs_ports:
            return f'9,,Bridge does not exist: {bridge}'

        cmd = ['ovs-appctl', 'fdb/flush', bridge]

        return self._run_cmd(cmd)

    def ovs_add_port(self, bridge, intf, vlan):
        '''Add a port with the given name to the existing bridge.  If vlan is
        not blank, then associate the port with that VLAN.  Otherwise,
        associate it with VLAN 0.  Return the result.'''

        if bridge not in self.ovs_ports:
            return f'9,,Bridge does not exist: {bridge}'
        if intf not in self.links:
            return f'9,,Interface does not exist: {intf}'

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

    def unshare_hostinit(self, hostname, net, hosts_file, mount_sys, use_vty,
            config_file, sys_cmd_helper_sock_remote, sys_cmd_helper_sock_local,
            comm_sock_remote, comm_sock_local, script_file):
        '''Run the hostinit module in a namespace that we have created, and
        return the result.'''

        nspath = os.path.join(RUN_NETNS_DIR, hostname)

        if net and nspath not in self.netns_exists:
            return f'9,,Namespace does not exist: {nspath}'

        cmd = ['unshare', '--mount', '--uts', f'--setuid={self._uid}']
        if net:
            cmd += [f'--net={nspath}']
        cmd += [sys.executable, '-m', HOSTINIT_MODULE,
                    '--hosts-file', hosts_file]
        if mount_sys:
            cmd += ['--mount-sys']
        if use_vty:
            vty = os.path.join(FRR_RUN_DIR, hostname)
            cmd += ['--vty-socket', vty]
        cmd += [config_file,
                sys_cmd_helper_sock_remote, sys_cmd_helper_sock_local,
                comm_sock_remote, comm_sock_local,
                script_file]

        cmd_str = ' '.join(cmd)
        logger.debug(cmd_str)
        p = subprocess.Popen(cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL)
        pid = str(p.pid)

        self.netns_mounted.add(hostname)
        self.netns_to_pid[hostname] = pid
        self.pid_to_netns[pid] = hostname

        ret = [0, cmd_str]
        return util.list_to_csv_str(ret)

    def start_rawpkt_helper(self, ns, *ints):
        '''Launch a process for passing packets from raw sockets to UNIX domain
        sockets and vice-versa using the RawPktHelperManager. Return the
        result.'''

        nspath = os.path.join(RUN_NETNS_DIR, ns)

        if ns not in self.netns_mounted:
            return f'9,,Namespace is not mounted: {nspath}'
        if ns not in self.netns_to_pid:
            return '9,,No PID associated with namespace'

        helper = RawPktHelperManager(self.netns_to_pid[ns], *ints)
        if helper.start():
            return '0,'
        return '9,,Helper not started'

    def _create_frr_conf_file(self, conf_file_path, contents):
        '''Create a configuration file for an FRR daemon.'''

        assert self._frr_uid is not None and self._frr_gid is not None, \
                'A uid/gid associated with frr must be set when frr is used'

        if os.path.exists(conf_file_path):
            return f'9,,Config file already exists: {conf_file_path}'

        frr_path = os.path.split(conf_file_path)[0]
        for path in (FRR_CONF_DIR, frr_path):
            if os.path.exists(path):
                continue

            val = self._mkdir(path, mode=0o750)
            if not val.startswith('0,'):
                return val

            val = self._chown(path, 0, self._frr_gid)
            if not val.startswith('0,'):
                self._rmdir(path)
                return val

        try:
            with open(conf_file_path, 'w') as fh:
                fh.write(contents)
        except OSError as e:
            parts = ['1', f'open({conf_file_path}, "w")', str(e)]
            return util.list_to_csv_str(parts)

        val = self._chown(conf_file_path, 0, self._frr_gid)
        if not val.startswith('0,'):
            return val

        val = self._chmod(conf_file_path, 0o640)
        if not val.startswith('0,'):
            return val

        return '0,'

    def _frr_daemon_running(self, hostname, pid_file):
        '''Return True if the FRR daemon corresponding to the hostname and
        pid_file is running, False otherwise.'''

        ns = hostname
        pid_file_path = os.path.join(FRR_RUN_DIR, ns, pid_file)

        try:
            pid = int(open(pid_file_path, 'r').read().strip())
        except (OSError, ValueError) as e:
            return False

        cmd = ['ps', '-p', str(pid)]
        val = self._run_cmd(cmd)
        return val.startswith('0,')

    def _start_frr_daemon(self, hostname, conf_file, pid_file,
            prog_path, started_set, contents):
        '''Prepare and start an FRR daemon.'''

        ns = hostname
        nspath = os.path.join(RUN_NETNS_DIR, ns)
        conf_file_path = os.path.join(FRR_CONF_DIR, ns, conf_file)

        if ns not in self.netns_mounted:
            return f'9,,Namespace is not mounted: {nspath}'
        if ns not in self.netns_to_pid:
            return '9,,No PID associated with namespace'
        if self._frr_daemon_running(hostname, pid_file):
            return '9,,Daemon still running'

        ret = self._create_frr_conf_file(conf_file_path, contents)
        if not ret.startswith('0,'):
            return ret

        cmd = [prog_path, '-d', '-N', ns, '-f', conf_file_path]
        val = self._run_cmd_netns(cmd, self.netns_to_pid[ns])
        if val.startswith('0,'):
            started_set.add(hostname)
        return val

    def start_zebra(self, hostname):
        '''Prepare and start the zebra FRR daemon.'''

        return self._start_frr_daemon(hostname, FRR_ZEBRA_CONF_FILE,
                FRR_ZEBRA_PID_FILE, FRR_ZEBRA_PROG, self.zebra_started,
                f'hostname {hostname}\n')

    def start_ripd(self, hostname, *ints):
        '''Prepare and start the ripd FRR daemon.'''

        contents = f'hostname {hostname}\n' + \
                'router rip\n redistribute connected\n'
        for intf in ints:
            contents += f' network {intf}\n'

        return self._start_frr_daemon(hostname, FRR_RIPD_CONF_FILE,
                FRR_RIPD_PID_FILE, FRR_RIPD_PROG, self.ripd_started,
                contents)

    def start_ripngd(self, hostname, *ints):
        '''Prepare and start the ripngd FRR daemon.'''

        contents = f'hostname {hostname}\n' + \
                'router ripng\n redistribute connected\n'
        for intf in ints:
            contents += f' network {intf}\n'

        return self._start_frr_daemon(hostname, FRR_RIPNGD_CONF_FILE,
                FRR_RIPNGD_PID_FILE, FRR_RIPNGD_PROG, self.ripngd_started,
                contents)

    def _kill_frr_daemon(self, hostname, conf_file, pid_file, vty_file,
            started_set):
        '''Send SIGTERM to an FRR daemon and then remove the associated config
        file and pid file.'''

        ns = hostname
        conf_file_path = os.path.join(FRR_CONF_DIR, ns, conf_file)
        pid_file_path = os.path.join(FRR_RUN_DIR, ns, pid_file)
        vty_file_path = os.path.join(FRR_RUN_DIR, ns, vty_file)

        if hostname not in started_set:
            return '9,,Daemon was not started'

        try:
            pid = int(open(pid_file_path, 'r').read().strip())
        except OSError as e:
            parts = ['1', f'open({pid_file_path}, "r")', str(e)]
            return util.list_to_csv_str(parts)
        except ValueError as e:
            parts = ['1', f'read({pid_file_path})', str(e)]
            return util.list_to_csv_str(parts)

        val = self._kill(pid, signal.SIGTERM)
        if not val.startswith('0,'):
            return val

        frr_run_path = os.path.split(pid_file_path)[0]
        frr_conf_path = os.path.split(conf_file_path)[0]

        self._unlink(conf_file_path)
        self._rmdir(frr_conf_path)

        self._unlink(pid_file_path)
        self._unlink(vty_file_path)
        self._rmdir(frr_run_path)

        started_set.remove(hostname)

        return '0,'


    def stop_zebra(self, hostname):
        '''Terminate and clean up after the zebra FRR daemon.'''

        val = self._kill_frr_daemon(hostname, FRR_ZEBRA_CONF_FILE,
                FRR_ZEBRA_PID_FILE, FRR_ZEBRA_VTY_FILE, self.zebra_started)

        if not val.startswith('0,'):
            return val

        ns = hostname
        zserv_file_path = os.path.join(FRR_RUN_DIR, ns, FRR_ZSERV_FILE)
        frr_run_path = os.path.split(zserv_file_path)[0]

        self._unlink(zserv_file_path)
        self._rmdir(frr_run_path)

        return '0,'


    def stop_ripd(self, hostname):
        '''Terminate and clean up after the ripd FRR daemon.'''

        return self._kill_frr_daemon(hostname, FRR_RIPD_CONF_FILE,
                FRR_RIPD_PID_FILE, FRR_RIPD_VTY_FILE, self.ripd_started)

    def stop_ripngd(self, hostname):
        '''Terminate and clean up after the ripngd FRR daemon.'''

        return self._kill_frr_daemon(hostname, FRR_RIPNGD_CONF_FILE,
                FRR_RIPNGD_PID_FILE, FRR_RIPNGD_VTY_FILE, self.ripngd_started)

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

        cmd_str = ' '.join(cmd)
        logger.debug(cmd_str)

        netns1 = self.pid_to_netns[pid]
        if netns1 not in self.netns_to_iproute:
            self.netns_to_iproute[netns1] = NetNS(netns1)
        ns = self.netns_to_iproute[netns1]

        kwargs = { 'dst': prefix }
        if next_hop:
            kwargs['gateway'] = next_hop
        if intf:
            try:
                idx = ns.link_lookup(ifname=intf)[0]
            except IndexError:
                return f'1,{cmd_str},Invalid interface: {intf}'
            kwargs['oif'] = idx

        try:
            ns.route('add', **kwargs)
        except (NetlinkError, OSError, struct.error) as e:
            parts = ['1', cmd_str, str(e)]
            return util.list_to_csv_str(parts)
        return '0,{cmd_str}'

    @require_netns
    def del_route(self, pid, prefix):
        '''Delete a route within the namespace associated with a given pid.'''

        cmd = ['ip', 'route', 'del', prefix]

        cmd_str = ' '.join(cmd)
        logger.debug(cmd_str)

        netns1 = self.pid_to_netns[pid]
        if netns1 not in self.netns_to_iproute:
            self.netns_to_iproute[netns1] = NetNS(netns1)
        ns = self.netns_to_iproute[netns1]

        kwargs = { 'dst': prefix }
        try:
            ns.route('del', **kwargs)
        except (NetlinkError, OSError, struct.error) as e:
            parts = ['1', cmd_str, str(e)]
            return util.list_to_csv_str(parts)
        return f'0,{cmd_str}'

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
            parts = util.csv_str_to_list(msg)
            try:
                if not parts[0].startswith('_') and \
                        hasattr(self, parts[0]):
                    func = getattr(self, parts[0])
                    status = func(*parts[1:])
                else:
                    status = f'9,,Invalid command: {parts[0]}'
            except Exception as e:
                status_list = [9, '', f'Command error: {msg.strip()}: {str(e)}']
                status = util.list_to_csv_str(status_list)
            if peer is not None:
                # only send a response if the other side has an address to send
                # it to
                try:
                    sock.sendto(status.encode('utf-8'), peer)
                except ConnectionRefusedError:
                    pass
