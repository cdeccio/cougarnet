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

import json
import os
import subprocess
import sys

from cougarnet import util

from .interface import PhysicalInterfaceConfig, VirtualInterfaceConfig

#TERM="xfce4-terminal"
TERM = "lxterminal"
HOSTINIT_MODULE = "cougarnet.virtualnet.hostinit"
MAIN_WINDOW_NAME = "main"
CMD_WINDOW_NAME = "prog"

FALSE_STRINGS = ('off', 'no', 'n', 'false', 'f', '0')

class HostConfig:
    '''The network configuration for a virtual host.'''

    attrs = { 'type': 'host',
            'native_apps': True,
            'terminal': True,
            'prog': None,
            'prog_window': None,
            'ipv6': True,
            'routes': None,
            }

    def __init__(self, hostname, sock_file, tmux_file, script_file, **kwargs):

        self.hostname = hostname
        self.sock_file = sock_file
        self.tmux_file = tmux_file
        self.script_file = script_file
        self.pid = None
        self.config_file = None
        self.next_int_num = 0
        self.int_by_name = {}
        self.int_by_neighbor = {}
        self.int_by_vlan = {}
        self.neighbor_by_int = {}
        self.neighbor_by_hostname = {}

        self.type = 'host'
        self.native_apps = True
        self.terminal = True
        self.prog = None
        self.prog_window = None
        self.ipv6 = True
        self.routes = None

        for attr in self.__class__.attrs:
            setattr(self, attr, kwargs.get(attr, self.__class__.attrs[attr]))

        self.has_bridge = False
        self.has_vlans = None
        self.hosts_file = None

        self.routes_pre_processed = self.routes
        self.routes = None

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

        self.create_script_file()

    def __str__(self):
        return self.hostname

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
                raise ValueError(f'The interface connected to {neighbor} ' + \
                        'is designated as a next hop for one of ' + \
                        f'{self.hostname}\'s routes, but {neighbor} ' + \
                        f'is not directly connected to {self.hostname}.') \
                        from None
            self.routes.append((prefix, intf.name, next_hop))

    def _host_config(self):
        '''Return a dictionary containing the network configuration for this
        virtual host.'''

        host_info = {
                'hostname': self.hostname,
                'routes': self.routes,
                'native_apps': self.native_apps,
                'type': self.type,
                'ipv6': self.ipv6
                }
        host_info['ip_forwarding'] = self.type == 'router' and self.native_apps
        int_infos = {}
        for intf in self.neighbor_by_int:
            int_infos[intf.name] = intf.as_dict()
        for vlan in self.int_by_vlan:
            intf = self.int_by_vlan[vlan]
            int_infos[intf.name] = intf.as_dict()
        host_info['interfaces'] = int_infos
        return host_info

    def create_config(self, config_file):
        '''Create the specified file with the network configuration associated
        with this virtual host.'''

        host_config = self._host_config()

        self.config_file = config_file
        with open(self.config_file, 'w') as fh:
            fh.write(json.dumps(host_config))

    def create_script_file(self):
        '''Create the script that is to be run by the virtual host after its
        network configuration has been applied.'''

        with open(self.script_file, 'w') as fh:
            fh.write('#!/bin/bash\n')
            fh.write(f'exec tmux -S {self.tmux_file} ' + \
                    f'new-session -s "{self.hostname}" -n "{MAIN_WINDOW_NAME}"')

            if self.terminal:
                # start attached
                fh.write(' \\; \\\n')
                # have server terminate when client detaches
                fh.write('    set exit-unattached on \\; \\\n')
            else:
                # start detached
                fh.write(' -d \\; \\\n')

            if self.prog is not None:
                # start script in window
                if self.prog_window == 'background':
                    fh.write(f'    new-window -n "{CMD_WINDOW_NAME}" \\; \\\n')
                prog = self.prog.replace('|', ' ').replace('"', r'\"')
                fh.write(f'    send-keys "{prog}" C-m \\; \\\n')
                fh.write(f'    select-window -t "{MAIN_WINDOW_NAME}" \\; \\\n')
                if self.prog_window == 'split':
                    # split window, and make new pane the focus
                    fh.write('    split-window -v \\; \\\n')

            # allow scrolling in window
            fh.write('    setw -g mouse on \\; \\\n')

            fh.write('\n')

        cmd = ['chmod', '755', self.script_file]
        subprocess.run(cmd, check=True)

    def create_hosts_file(self, other_hosts, hosts_file):
        '''Create the hosts file for this virtual host.'''

        self.hosts_file = hosts_file

        with open(self.hosts_file, 'w') as write_fh:
            write_fh.write(f'127.0.0.1 localhost {self.hostname}\n')
            if self.ipv6:
                write_fh.write(f'::1 localhost {self.hostname}\n')
            with open(other_hosts, 'r') as read_fh:
                write_fh.write(read_fh.read())

    def create_hosts_file_entries(self, fh):
        '''Create the hosts file entries associated with the hostname-interface
        mappings for this virtual host.'''

        for intf in self.neighbor_by_int:
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

    def start(self, commsock_file):
        '''Start this virtual host.  Call unshare to create the new namespace,
        initialize the virtual network within the new namespace, and start the
        designated program within the new namespace.'''

        assert self.config_file is not None, \
                "create_config() must be called before start()"

        cmd = ['sudo', 'touch', f'/run/netns/{self.hostname}']
        subprocess.run(cmd, check=False)

        cmd = ['sudo', '-E', 'unshare', '--mount']
        if not (self.type == 'switch' and self.native_apps):
            cmd += [f'--net=/run/netns/{self.hostname}']
        cmd += ['--uts', sys.executable, '-m', HOSTINIT_MODULE,
                    '--hosts-file', self.hosts_file,
                    '--user', os.environ.get("USER")]

        cmd += ['--prog', self.script_file]
        if not (self.type == 'switch' and self.native_apps):
            cmd += ['--mount-sys']

        cmd += [self.config_file, commsock_file, self.sock_file]

        if self.terminal:
            cmd_quoted = []
            for c in cmd:
                c = c.replace('"', r'\"')
                c = f'"{c}"'
                cmd_quoted.append(c)
            subcmd = ' '.join(cmd_quoted)

            cmd = [TERM, '-t', f'{self.type.capitalize()}: {self.hostname}', '-e', subcmd]

        subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def add_int(self, name, neighbor, **kwargs):
        '''Add a new interface on this virtual host with the specified name,
        neighbor, and attributes.'''

        if neighbor in self.int_by_neighbor:
            raise ValueError('Only one link can exist between two hosts')

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
            raise ValueError('A VLAN can only be assigned to one interface.')

        intf = VirtualInterfaceConfig(phys_int, vlan)
        self.int_by_vlan[vlan] = intf
        return intf

    def next_int(self):
        '''Return the number associated with the next interfacei, for a unique
        name.'''

        int_next = self.next_int_num
        self.next_int_num += 1
        return int_next

    def kill(self):
        '''Send signals to the program being run within the tmux process being
        run by unshare, until it is terminated.  If the tmux server process
        persists, then send signals to it, until it is terminated.'''

        if self.pid is not None:
            util.kill_until_terminated(self.pid, elevate_if_needed=True)

        if self.tmux_file is not None:
            tmux_pid = self._get_tmux_server_pid()
            if tmux_pid is not None:
                util.kill_until_terminated(tmux_pid, elevate_if_needed=False)

    def cleanup(self):
        '''Shut down and clean up resources allocated for the this virtual
        host, including processes, interfaces, and files.'''

        self.kill()

        #XXX not sure why this while loop is necessary (i.e., why we need to
        #XXX umount several times)
        while True:
            cmd = ['sudo', 'umount', f'/run/netns/{self.hostname}']
            try:
                subprocess.run(cmd, stderr=subprocess.DEVNULL, check=True)
            except subprocess.CalledProcessError:
                break

        if os.path.exists(f'/run/netns/{self.hostname}'):
            cmd = ['sudo', 'rm', f'/run/netns/{self.hostname}']
            subprocess.run(cmd, check=False)

        if self.type == 'switch' and self.native_apps:
            cmd = ['sudo', 'ovs-vsctl', 'del-br', self.hostname]
            subprocess.run(cmd, check=False)

            # Explicitly deleting interfaces is only needed when this is a
            # switch running in "native apps" mode; otherwise, the interfaces
            # were deleted when the process with the namespace ended.
            for intf in self.neighbor_by_int:
                cmd = ['sudo', 'ip', 'link', 'del', intf.name]
                subprocess.run(cmd, check=False)

        for f in self.sock_file, self.config_file, self.script_file, \
                self.hosts_file, self.tmux_file:
            if f is not None and os.path.exists(f):
                os.unlink(f)

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
