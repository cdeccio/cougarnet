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

'''Classes and functions for maintaining network configurations for virtual
hosts.'''

import ipaddress
import json
import logging
import os
import subprocess
import sys
import time

from cougarnet.errors import ConfigurationError
from cougarnet.globals import *
from cougarnet.sys_helper import cmd_helper
from cougarnet.sys_helper.cmd_helper import sys_cmd
from cougarnet import util

from .cmd import run_cmd
from .interface import LoopbackInterfaceConfig, \
        PhysicalInterfaceConfig, VirtualInterfaceConfig

logger = logging.getLogger(__name__)

class HostConfig:
    '''The network configuration for a virtual host.'''

    attrs = { 'type': 'host',
            'native_apps': True,
            'terminal': True,
            'prog': None,
            'prog_window': None,
            'ipv6': True,
            'routes': None,
            'routers': None,
            'loopback_addrs': None,
            }

    def __init__(self, hostname, hostdir, cwd, bash_history, vtysh_history,
                 sys_cmd_helper_local, comm_sock_file,
                 sys_net_helper_raw_dir, sys_net_helper_user_dir,
                 tmux_file, startup_script_file, pid_file,
                 env_file, **kwargs):

        self.hostname = hostname
        self.hostdir = hostdir
        self.cwd = cwd
        self.bash_history = bash_history
        self.vtysh_history = vtysh_history
        self.sys_cmd_helper_local = sys_cmd_helper_local
        self.comm_sock_file = comm_sock_file
        self.sys_net_helper_raw_dir = sys_net_helper_raw_dir
        self.sys_net_helper_user_dir = sys_net_helper_user_dir
        self.tmux_file = tmux_file
        self.startup_script_file = startup_script_file
        self.pid_file = pid_file
        self.env_file = env_file
        self.pid = None
        self.config_file = None
        self.next_int_num = 0
        self.int_by_name = {}
        self.int_by_neighbor = {}
        self.int_by_vlan = {}
        self.neighbor_by_int = {}
        self.neighbor_by_hostname = {}
        self.helper_sock_pair_by_int = {}

        for attr in self.__class__.attrs:
            setattr(self, attr, kwargs.get(attr, self.__class__.attrs[attr]))

        self.has_bridge = False
        self.has_vlans = None
        self.hosts_file = None

        self.routes_pre_processed = self.routes
        self.routes = None

        if self.routers:
            self.routers = self.routers.split(';')
        else:
            self.routers = []
        for router in self.routers:
            if router not in ALLOWED_ROUTERS:
                raise ConfigurationError(
                        f'{router} is not an allowed router.')

        loopback_addrs = []
        if self.loopback_addrs is not None:
            for loopback_addr in self.loopback_addrs.split(';'):
                try:
                    ipaddress.ip_address(loopback_addr)
                except ValueError:
                    raise ConfigurationError(
                            f'Invalid IP Address: {loopback_addr}')
                loopback_addrs.append(loopback_addr)
        self.loopback_addrs = loopback_addrs

        if not self.native_apps or \
                str(self.native_apps).lower() in FALSE_STRINGS:
            self.native_apps = False
        else:
            self.native_apps = True
        if not self.terminal or \
                str(self.terminal).lower() in FALSE_STRINGS:
            self.terminal = False
        else:
            self.terminal = True
        if not self.ipv6 or \
                str(self.ipv6).lower() in FALSE_STRINGS or \
                self.type == 'switch':
            self.ipv6 = False
        else:
            self.ipv6 = True

        self._create_dirs()
        self.create_startup_script_file()

    def __str__(self):
        return self.hostname

    def set_pid(self, pid):
        '''Assign the specified pid to the pid member variable.  Store the
        namespace info associated with this process in the helper, so commands
        can be run.  Finally, write the pid to the pid file.'''

        self.pid = pid
        #XXX This line is redundant when calling update_pid()
        run_cmd('store_ns_info', str(self.pid))
        with open(self.pid_file, 'w') as fh:
            fh.write(str(self.pid))

    def update_pid(self):
        '''tmux daemonizes by forking a child process and then having the
        parent terminate, i.e., so the child is a daemon.  This method is
        called after this daemonization has happened.  waitpid() is called on
        the tmux parent -- which is a child process of the system command
        helper.  Then the pid of the daemonized tmux process is retrieved, and
        the pid is updated in the system command helper.  set_pid() is called,
        which writes the updated pid to the file and stores the updated
        namespace info.'''

        oldpid = self.pid
        sys_cmd(['waitpid', str(oldpid)], check=True)
        newpid = self._get_tmux_server_pid()
        sys_cmd(['update_pid', str(oldpid), str(newpid)], check=True)
        self.set_pid(newpid)

    def _create_dirs(self):
        for d in (self.hostdir,
                  self.sys_net_helper_raw_dir, self.sys_net_helper_user_dir):
            logger.debug(' '.join(['mkdir', d]))
            os.mkdir(d)

    def _get_tmux_server_pid(self):
        '''Return the PID associated with the tmux server for this virtual
        host, or None, if there is no tmux server running.'''

        if self.tmux_file is None:
            return None
        cmd = ['tmux', '-S', self.tmux_file,
                'display-message', '-pF', '#{pid}']
        output = subprocess.run(cmd,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.PIPE, check=False).stdout
        if output:
            return int(output.decode('utf-8').strip())
        return None

    def process_routes(self):
        '''Parse the string containing the manual routes contained in the
        routes_pre_processed instance variable, and create a list of three
        tuples representing those routes as the routes instance variable.'''

        self.routes = []

        if self.routes_pre_processed is None:
            return

        routes = self.routes_pre_processed.split(';')
        for route in routes:
            prefix, neighbor, next_hop = route.split('|')
            if not next_hop:
                next_hop = None
            try:
                intf = self.int_by_neighbor[self.neighbor_by_hostname[neighbor]]
            except KeyError:
                #XXX At the moment, this results in the ConfigurationError()
                # instance being set with the line number corresponding to the
                # last line in the config file, which doesn't make any sense in
                # this case.  We need to find a better way to report this error.
                raise ConfigurationError(f'The interface connected to ' + \
                        f'{neighbor} is designated as a next hop for one ' + \
                        f'of {self.hostname}\'s routes, but {neighbor} ' + \
                        f'is not directly connected to {self.hostname}.') \
                        from None
            self.routes.append((prefix, intf.name, next_hop))

    def _helper_sock_pair_for_user(self):
        int_to_sock = {}
        for intf in self.helper_sock_pair_by_int:
            int_to_sock[intf] = {
                    'remote': self.helper_sock_pair_by_int[intf][0],
                    'local': self.helper_sock_pair_by_int[intf][1]
                    }
        return int_to_sock

    def _host_config(self, comm_sock_file):
        '''Return a dictionary containing the network configuration for this
        virtual host.'''

        int_infos = {}
        for intf in self.neighbor_by_int:
            int_infos[intf.name] = intf.as_dict()
        if self.loopback_addrs:
            ipv4_addrs = [addr for addr in self.loopback_addrs if \
                    ':' not in addr]
            ipv6_addrs = [addr for addr in self.loopback_addrs if \
                    ':' in addr]
            loopback = LoopbackInterfaceConfig('lo', ipv4_addrs, ipv6_addrs)
            int_infos['lo'] = loopback.as_dict()
        for vlan in self.int_by_vlan:
            intf = self.int_by_vlan[vlan]
            int_infos[intf.name] = intf.as_dict()

        if self.type == 'router' and self.native_apps:
            vty_file = os.path.join(FRR_RUN_DIR, self.hostname)
        else:
            vty_file = None

        host_info = {
                'hostname': self.hostname,
                'type': self.type,
                'native_apps': self.native_apps,
                'mount_sys': not (self.type == 'switch' and self.native_apps),
                'sys_cmd_helper_sock': {
                    'local': self.sys_cmd_helper_local,
                    'remote': cmd_helper.sys_cmd_helper.remote_sock_path,
                    },
                'comm_sock': {
                    'local': self.comm_sock_file,
                    'remote': comm_sock_file,
                    },
                'startup_script': self.startup_script_file,
                'vty_socket': vty_file,
                'hosts_file': self.hosts_file,
                'routes': self.routes,
                'ipv6': self.ipv6,
                'int_to_sock': self._helper_sock_pair_for_user(),
                'interfaces': int_infos,
                'ip_forwarding': self.type == 'router' and self.native_apps,
                }
        return host_info

    def create_config(self, config_file, comm_sock_file):
        '''Create the specified file with the network configuration associated
        with this virtual host.'''

        host_config = self._host_config(comm_sock_file)

        self.config_file = config_file
        fd = os.open(self.config_file, os.O_WRONLY | os.O_CREAT, 0o644)
        with open(fd, 'w') as fh:
            fh.write(json.dumps(host_config))

    def create_startup_script_file(self):
        '''Create the script that is to be run by the virtual host after its
        network configuration has been applied.'''

        fd = os.open(self.startup_script_file, os.O_WRONLY | os.O_CREAT, 0o755)
        with open(fd, 'w') as fh:
            fh.write('#!/bin/bash\n')
            fh.write(f'. {self.env_file}\n')
            fh.write(f'export HISTFILE={self.bash_history}\n\n')
            fh.write(f'export VTYSH_HISTFILE={self.vtysh_history}\n\n')
            fh.write(f'exec tmux -S {self.tmux_file} ' + \
                    'set -g default-terminal "tmux-256color" \\; \\\n' + \
                    f'new-session -s "{self.hostname}" ' + \
                    f'-n "{MAIN_WINDOW_NAME}" -d \\; \\\n')

            ready_cmd = f'{sys.executable} -m {HOSTREADY_MODULE}'
            if self.prog is not None:
                # start script in window
                if self.prog_window == 'background':
                    fh.write(f'    new-window -n "{CMD_WINDOW_NAME}" \\; \\\n')
                prog = self.prog.replace('|', ' ').replace('"', r'\"')
                if not os.path.isabs(prog) and self.cwd:
                    prog = os.path.join(self.cwd, prog)
                fh.write(f'    send-keys "{ready_cmd}" C-m \\; \\\n')
                fh.write(f'    send-keys "history -c ; clear" C-m \\; \\\n')
                fh.write(f'    send-keys "{prog}" C-m \\; \\\n')
                fh.write(f'    select-window -t "{MAIN_WINDOW_NAME}" \\; \\\n')
                if self.prog_window == 'split':
                    # split window, and make new pane the focus
                    fh.write('    split-window -v \\; \\\n')
            else:
                fh.write(f'    send-keys "{ready_cmd}" C-m \\; \\\n')
                fh.write(f'    send-keys "history -c ; clear" C-m \\; \\\n')

            # allow scrolling in window
            fh.write('    setw -g mouse on \\; \\\n')

            fh.write('\n')

    def create_hosts_file(self, other_hosts, hosts_file):
        '''Create the hosts file for this virtual host.'''

        self.hosts_file = hosts_file

        fd = os.open(self.hosts_file, os.O_WRONLY | os.O_CREAT, 0o644)
        with open(fd, 'w') as write_fh:
            write_fh.write(f'127.0.0.1 localhost {self.hostname}\n')
            if self.ipv6:
                write_fh.write(f'::1 localhost {self.hostname}\n')
            with open(other_hosts, 'r') as read_fh:
                write_fh.write(read_fh.read())

    def create_hosts_file_entries(self, fh):
        '''Create the hosts file entries associated with the hostname-interface
        mappings for this virtual host.'''

        for intf in list(self.neighbor_by_int) + \
                [i for v, i in self.int_by_vlan.items()]:
            for addr in intf.ipv4_addrs:
                slash = addr.find('/')
                if slash >= 0:
                    addr = addr[:slash]
                fh.write(f'{addr} {self.hostname}\n')
            for addr in intf.ipv6_addrs:
                slash = addr.find('/')
                if slash >= 0:
                    addr = addr[:slash]
                fh.write(f'{addr} {self.hostname}\n')

    def start_raw_packet_helper(self):
        '''Start a process that will listen for packets on a raw socket and
        immediately send them to a specified UNIX domain socket, so they can be
        seen by an unprivileged process.'''

        ints = [f'{i}={s[0]}:{s[1]}' \
                for i, s in self.helper_sock_pair_by_int.items()]
        run_cmd('start_rawpkt_helper', self.hostname, *ints)

    def start_router(self):
        '''Start the zebra and rip routing processes that will manage routing
        on the device.'''

        if self.type == 'router' and self.native_apps:
            ints = [i for i, s in self.int_by_name.items()]
            run_cmd('start_zebra', self.hostname)
            if 'rip' in self.routers:
                run_cmd('start_ripd', self.hostname, *ints)
            if 'ripng' in self.routers:
                run_cmd('start_ripngd', self.hostname, *ints)

    def start(self):
        '''Start this virtual host.  Call unshare to create the new namespace,
        initialize the virtual network within the new namespace, and start the
        designated program within the new namespace.'''

        assert self.config_file is not None, \
                "create_config() must be called before start()"

        run_cmd('add_netns', self.hostname)

        args = [self.hostname]
        if not (self.type == 'switch' and self.native_apps):
            args += [self.hostname]
        else:
            args += ['']
        args += [self.config_file]
        run_cmd('unshare_hostinit', *args)

    def flush_forwarding_table(self):
        '''If we are a switch running native_apps mode, send the OVS command
        to flush the forwarding table.'''

        if self.type == 'switch' and self.native_apps:
            run_cmd('ovs_flush_bridge', self.hostname)

    def attach_terminal(self):
        '''If terminal mode is enabled for this host, launch the terminal and
        run tmux to attach it with the tmux session already created for the
        virtual host.'''

        if self.terminal and self.tmux_file is not None:
            #XXX fix this - either make a notification or add a timeout
            while not os.path.exists(self.tmux_file):
                time.sleep(0.1)

            cmd = [TERM, '-t',
                f'{self.type.capitalize()}: {self.hostname}',
                '-e', f'tmux -S {self.tmux_file} attach \\; ' + \
                        'set exit-unattached on \\;']
            logger.debug(' '.join(cmd))
            return subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return None

    def add_int(self, name, neighbor, **kwargs):
        '''Add a new interface on this virtual host with the specified name,
        neighbor, and attributes.'''

        if neighbor in self.int_by_neighbor:
            raise ConfigurationError('Only one link can exist ' + \
                    'between two hosts')

        intf = PhysicalInterfaceConfig(name, **kwargs)
        self.int_by_name[name] = intf
        self.int_by_neighbor[neighbor] = intf
        self.neighbor_by_int[intf] = neighbor
        self.neighbor_by_hostname[neighbor.hostname] = neighbor
        return intf

    def add_vlan(self, phys_int, vlan):
        '''Add a new VLAN interface on this virtual host with the specified
        VLAN ID.'''

        if vlan in self.int_by_vlan:
            raise ConfigurationError('A VLAN can only be assigned to ' + \
                    'one interface.')

        intf = VirtualInterfaceConfig(phys_int, vlan)
        self.int_by_vlan[vlan] = intf
        return intf

    def next_int(self):
        '''Return the number associated with the next interface, for a unique
        name.'''

        int_next = self.next_int_num
        self.next_int_num += 1
        return int_next

    def kill(self):
        '''Send signals to the program being run within the tmux process being
        run by unshare, until it is terminated.  If the tmux server process
        persists, then send signals to it, until it is terminated.'''

        if self.pid is not None:
            util.kill_until_terminated(self.pid)

        if self.tmux_file is not None:
            tmux_pid = self._get_tmux_server_pid()
            if tmux_pid is not None:
                util.kill_until_terminated(tmux_pid)

    def cleanup(self):
        '''Shut down and clean up resources allocated for the this virtual
        host, including processes, interfaces, and files.'''

        if self.type == 'router' and self.native_apps:
            if 'rip' in self.routers:
                sys_cmd(['stop_ripd', self.hostname], check=False)
            if 'ripng' in self.routers:
                sys_cmd(['stop_ripngd', self.hostname], check=False)
            sys_cmd(['stop_zebra', self.hostname], check=False)

        self.kill()

        if self.pid_file is not None and os.path.exists(self.pid_file):
            logger.debug(' '.join(['rm', self.pid_file]))
            os.unlink(self.pid_file)

        sys_cmd(['umount_netns', self.hostname], check=False)
        sys_cmd(['del_netns', self.hostname], check=False)

        if self.type == 'switch' and self.native_apps:
            sys_cmd(['ovs_del_bridge', self.hostname], check=False)

        for vlan in self.int_by_vlan:
            sys_cmd(['del_link', self.int_by_vlan[vlan].name], check=False)

        for intf in self.neighbor_by_int:
            sys_cmd(['del_link', intf.name], check=False)

        for intf in self.helper_sock_pair_by_int:
            sock1, sock2 = self.helper_sock_pair_by_int[intf]
            if os.path.exists(sock1):
                logger.debug(' '.join(['rm', sock1]))
                os.unlink(sock1)
            if os.path.exists(sock2):
                logger.debug(' '.join(['rm', sock2]))
                os.unlink(sock2)

        for f in self.comm_sock_file, self.config_file, \
                self.startup_script_file, self.sys_cmd_helper_local, \
                self.hosts_file, self.tmux_file:
            if f is not None and os.path.exists(f):
                logger.debug(' '.join(['rm', f]))
                os.unlink(f)

        for d in (self.sys_net_helper_raw_dir, self.sys_net_helper_user_dir,
                  self.hostdir):
            logger.debug(' '.join(['rmdir', d]))
            os.rmdir(d)

    def label_for_int(self, intf):
        '''Return a GraphViz HTML-like label for a given interface on this
        virtual host.'''

        s = f'<TR><TD COLSPAN="2" ALIGN="left"><B>{intf.name}:</B></TD></TR>'
        if intf.mac_addr is not None:
            s += f'<TR><TD ALIGN="right">  </TD><TD>{intf.mac_addr}</TD></TR>'
        if intf.ipv4_addrs:
            s += '<TR><TD ALIGN="RIGHT">  </TD><TD>'
            s += '</TD></TR><TR><TD ALIGN="right">'.join(intf.ipv4_addrs)
            s += '</TD></TR>'
        if intf.ipv6_addrs:
            s += '<TR><TD ALIGN="RIGHT">  </TD><TD>'
            s += '</TD></TR><TR><TD ALIGN="right">'.join(intf.ipv6_addrs)
            s += '</TD></TR>'
        return s
