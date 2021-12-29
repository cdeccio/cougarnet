import json
import os
import subprocess
import sys
import time

from cougarnet import util

#TERM="xfce4-terminal"
TERM = "lxterminal"
HOSTPREP_MODULE = "cougarnet.hostprep"

FALSE_STRINGS = ('off', 'no', 'n', 'false', 'f', '0')

class Host(object):
    def __init__(self, hostname, sock_file, tmux_file, script_file, type='host',
            native_apps=True, terminal=True, prog=None, ipv6=True, routes=None):

        self.hostname = hostname
        self.sock_file = sock_file
        self.tmux_file = tmux_file
        self.script_file = script_file
        self.pid = None
        self.config_file = None
        self.next_int_num = 0
        self.int_to_neighbor = {}
        self.neighbor_to_int = {}
        self.neighbor_by_hostname = {}
        self.int_to_mac = {}
        self.int_to_ip4 = {}
        self.int_to_ip6 = {}
        self.int_to_bw = {}
        self.int_to_delay = {}
        self.int_to_loss = {}
        self.int_to_mtu = {}
        self.int_to_vlan = {}
        self.int_to_trunk = {}
        self.type = type
        self.prog = prog
        self.has_bridge = False
        self.has_vlans = None
        self.hosts_file = None
        self.routes_pre_processed = routes
        self.routes = None

        if not native_apps or str(native_apps).lower() in FALSE_STRINGS:
            self.native_apps = False
        else:
            self.native_apps = True
        if not terminal or str(terminal).lower() in FALSE_STRINGS:
            self.terminal = False
        else:
            self.terminal = True
        if not ipv6 or str(ipv6).lower() in FALSE_STRINGS:
            self.ipv6 = False
        else:
            self.ipv6 = True

        self.create_script_file()

    def __str__(self):
        return self.hostname

    def _get_tmux_server_pid(self):
        if self.tmux_file is None:
            return
        cmd = ['tmux', '-S', self.tmux_file,
                'display-message', '-pF', '#{pid}']
        output = subprocess.run(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE).stdout
        if output:
            return int(output.decode('utf-8').strip())
        else:
            return None

    def process_routes(self):
        self.routes = []

        if self.routes_pre_processed is None:
            return

        routes = self.routes_pre_processed.split(';')
        for route in routes:
            prefix, neighbor, next_hop = route.split('|')
            if not next_hop:
                next_hop = None
            try:
                intf = self.neighbor_to_int[self.neighbor_by_hostname[neighbor]]
            except KeyError:
                raise ValueError(f"The interface connected to {neighbor} " + \
                        f"is designated as a next hop for one of " + \
                        f"{self.hostname}'s routes, but {neighbor} " + \
                        f"is not directly connected to {self.hostname}.")
            self.routes.append((prefix, intf, next_hop))

    def _host_config(self):
        host_info = {
                'hostname': self.hostname,
                'routes': self.routes,
                'native_apps': self.native_apps,
                'type': self.type,
                'ipv6': self.ipv6
                }
        host_info['ip_forwarding'] = self.type == 'router' and self.native_apps
        int_infos = {}
        for intf in self.int_to_neighbor:
            int_infos[intf] = self._int_config(intf)
        host_info['interfaces'] = int_infos
        return host_info

    def _int_config(self, intf):
        return {
                'mac': self.int_to_mac[intf],
                'addrs4': self.int_to_ip4[intf][:],
                'addrs6': self.int_to_ip6[intf][:],
                'bw': self.int_to_bw[intf],
                'delay': self.int_to_delay[intf],
                'loss': self.int_to_loss[intf],
                'mtu': self.int_to_mtu[intf],
                'vlan': self.int_to_vlan[intf],
                'trunk': self.int_to_trunk[intf]
                }

    def create_config(self, config_file):

        host_config = self._host_config()

        self.config_file = config_file
        with open(self.config_file, 'w') as fh:
            fh.write(json.dumps(host_config))

    def create_script_file(self):

        with open(self.script_file, 'w') as fh:
            fh.write('#!/bin/bash\n')
            if self.terminal:
                fh.write(f'exec tmux -S {self.tmux_file} new-session \\; \\\n')
                fh.write(f'    set exit-unattached on \\; \\\n')
                if self.prog is not None:
                    prog = self.prog.replace('|', ' ').replace('"', r'\"')
                    fh.write(f'    send-keys "{prog}" C-m \\; \\\n')
                    fh.write(f'    split-window -v \\;\n')

            else:
                if self.prog is not None:
                    prog = self.prog.replace('|', ' ')
                    fh.write(f'exec {prog}')
                else:
                    fh.write(f'exec bash')

        cmd = ['chmod', '755', self.script_file]
        subprocess.run(cmd, check=True)

    def create_hosts_file(self, other_hosts, hosts_file):
        self.hosts_file = hosts_file

        with open(self.hosts_file, 'w') as write_fh:
            write_fh.write(f'127.0.0.1 localhost {self.hostname}\n')
            if self.ipv6:
                write_fh.write(f'::1 localhost {self.hostname}\n')
            with open(other_hosts, 'r') as read_fh:
                write_fh.write(read_fh.read())

    def create_hosts_file_entries(self, fh):
        for intf in self.int_to_neighbor:
            for addr in self.int_to_ip4[intf]:
                slash = addr.find('/')
                if slash >= 0:
                    addr = addr[:slash]
                fh.write(f'{addr} {self.hostname}\n')
            for addr in self.int_to_ip6[intf]:
                slash = addr.find('/')
                if slash >= 0:
                    addr = addr[:slash]
                fh.write(f'{addr} {self.hostname}\n')

    def start(self, commsock_file):
        assert self.config_file is not None, \
                "create_config() must be called before start()"

        cmd = ['sudo', 'touch', f'/run/netns/{self.hostname}']
        subprocess.run(cmd)

        cmd = ['sudo', '-E', 'unshare', '--mount']
        if not (self.type == 'switch' and self.native_apps):
            cmd += [f'--net=/run/netns/{self.hostname}']
        cmd += ['--uts', sys.executable, '-m', f'{HOSTPREP_MODULE}',
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

        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def add_int(self, intf, host):
        self.int_to_neighbor[intf] = host
        if host in self.neighbor_to_int:
            raise ValueError('Only one link can exist between two hosts')
        self.neighbor_to_int[host] = intf
        self.neighbor_by_hostname[host.hostname] = host

    def next_int(self):
        int_next = self.next_int_num
        self.next_int_num += 1
        return int_next

    def kill(self):
        if self.pid is not None:
            cmd = ['kill', f'-TERM', str(self.pid)]
            subprocess.run(cmd, stderr=subprocess.DEVNULL)

            if util.pid_is_running(self.pid):
                time.sleep(0.2)
                if util.pid_is_running(self.pid):
                    cmd = ['kill', f'-KILL', str(self.pid)]
                    subprocess.run(cmd, stderr=subprocess.DEVNULL)

        if self.tmux_file is not None:
            tmux_pid = self._get_tmux_server_pid()
            if tmux_pid is not None and \
                    util.pid_is_running(tmux_pid):
                cmd = ['kill', f'-TERM', str(tmux_pid)]
                subprocess.run(cmd, stderr=subprocess.DEVNULL)

                if util.pid_is_running(tmux_pid):
                    time.sleep(0.2)
                    if util.pid_is_running(tmux_pid):
                        cmd = ['kill', f'-KILL', str(tmux_pid)]
                        subprocess.run(cmd, stderr=subprocess.DEVNULL)


    def cleanup(self):
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
            subprocess.run(cmd)

        if self.type == 'switch' and self.native_apps:
            cmd = ['sudo', 'ovs-vsctl', 'del-br', self.hostname]
            subprocess.run(cmd)

            for intf in self.int_to_neighbor:
                neighbor = self.int_to_neighbor[intf]
                if neighbor.type == 'switch' and neighbor.native_apps:
                    cmd = ['sudo', 'ip', 'link', 'del', intf]
                    subprocess.run(cmd)

        for f in self.sock_file, self.config_file, self.script_file, \
                self.hosts_file, self.tmux_file:
            if f is not None and os.path.exists(f):
                os.unlink(f)

    def label_for_int(self, intf):
        s = f'<TR><TD COLSPAN="2" ALIGN="left"><B>{intf}:</B></TD></TR>'
        if self.int_to_mac[intf] is not None:
            s += f'<TR><TD ALIGN="right">  </TD><TD>{self.int_to_mac[intf]}</TD></TR>'
        if self.int_to_ip4[intf]:
            s += '<TR><TD ALIGN="RIGHT">  </TD><TD>'
            s += '</TD></TR><TR><TD ALIGN="right">'.join(self.int_to_ip4[intf])
            s += '</TD></TR>'
        if self.int_to_ip6[intf]:
            s += '<TR><TD ALIGN="RIGHT">  </TD><TD>'
            s += '</TD></TR><TR><TD ALIGN="right">'.join(self.int_to_ip6[intf])
            s += '</TD></TR>'
        return s

