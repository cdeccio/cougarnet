#!/usr/bin/python3

import argparse
import csv
import io
import ipaddress
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')

#TERM="xfce4-terminal"
TERM="lxterminal"
HOSTPREP_MODULE="cougarnet.hostprep"
TMPDIR="./tmp"

FALSE_STRINGS = ('off', 'no', 'n', 'false', 'f', '0')

class HostNotStarted(Exception):
    pass

class InconsistentConfiguration(Exception):
    pass

class Host(object):
    def __init__(self, hostname, gw4=None, gw6=None, type='host', \
            native_apps=True, terminal=True, prog=None):
        self.hostname = hostname
        self.pid = None
        self.pidfile = None
        self.config_file = None
        self.next_int_num = 0
        self.int_to_neighbor = {}
        self.neighbor_to_int = {}
        self.int_to_mac = {}
        self.int_to_ip4 = {}
        self.int_to_ip6 = {}
        self.int_to_bw = {}
        self.int_to_delay = {}
        self.int_to_loss = {}
        self.int_to_vlan = {}
        self.int_to_trunk = {}
        self.gw4 = gw4
        self.gw6 = gw6
        self.type = type
        self.prog = prog
        self.has_bridge = False
        self.has_vlans = None

        if not native_apps or str(native_apps).lower() in FALSE_STRINGS:
            self.native_apps = False
        else:
            self.native_apps = True
        if not terminal or str(terminal).lower() in FALSE_STRINGS:
            self.terminal = False
        else:
            self.terminal = True

    def __str__(self):
        return self.hostname

    def _host_config(self):
        s = io.StringIO()
        s.write(f'{self.hostname} ')
        attrs_tuple = (('gw4', self.gw4), ('gw6', self.gw6),
                ('native_apps', str(self.native_apps)),
                ('type', self.type))
        attrs_str = ['='.join(pair) for pair in attrs_tuple if pair[1] is not None]
        csv_writer = csv.writer(s)
        csv_writer.writerow(attrs_str)
        return s.getvalue()

    def _int_config(self, intf):
        #TODO change this to YAML
        s = io.StringIO()
        if self.int_to_mac[intf] is not None:
            mac = self.int_to_mac[intf]
        else:
            mac = ''
        s.write(f'{intf},{mac}')
        for addr in self.int_to_ip4[intf]:
            s.write(f',{addr}')
        for addr in self.int_to_ip6[intf]:
            s.write(f',{addr}')

        attrs_tuple = [('bw', self.int_to_bw[intf]),
                ('delay', self.int_to_delay[intf]),
                ('loss', self.int_to_loss[intf]),
                ('vlan', self.int_to_vlan[intf]),
                ('trunk', str(self.int_to_trunk[intf]))]

        attrs_str = ['='.join(pair) for pair in attrs_tuple if pair[1] is not None]
        if attrs_str:
            s.write(' ')
            csv_writer = csv.writer(s)
            csv_writer.writerow(attrs_str)
        else:
            s.write('\n')
        return s.getvalue()

    def create_config(self):
        cmd = ['mkdir', '-p', TMPDIR]
        subprocess.run(cmd)
        fd, self.config_file = tempfile.mkstemp(suffix='.cfg',
                prefix=f'{self.hostname}-', dir=TMPDIR)

        with os.fdopen(fd, 'w') as fh:
            host_config = self._host_config()
            fh.write(f'{host_config}')
            for intf in self.int_to_neighbor:
                if (self.type == 'switch' and self.native_apps) and \
                        not (self.int_to_neighbor[intf].type == 'switch' and \
                                self.int_to_neighbor[intf].native_apps):
                    continue
                int_config = self._int_config(intf)
                fh.write(f'{int_config}')

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

    def start(self, hosts_file, comm_sock):
        assert self.config_file is not None, \
                "create_config() must be called before start()"

        cmd = ['sudo', 'mkdir', '-p', '/run/netns']
        subprocess.run(cmd, check=True)

        cmd = ['sudo', 'touch', f'/run/netns/{self.hostname}']
        subprocess.run(cmd)

        cmd = ['mkdir', '-p', TMPDIR]
        subprocess.run(cmd)
        fd, self.pidfile = tempfile.mkstemp(suffix='.pid',
                prefix=f'{self.hostname}-', dir=TMPDIR)
        os.close(fd)

        cmd = ['sudo', '-E', 'unshare', '--mount']
        if not (self.type == 'switch' and self.native_apps):
            cmd += [f'--net=/run/netns/{self.hostname}']
        cmd += ['--uts', sys.executable, '-m', f'{HOSTPREP_MODULE}',
                    '--comm-sock', comm_sock, '--hosts-file',
                    hosts_file, '--user', os.environ.get("USER")]

        if self.prog is not None:
            cmd += ['--prog', self.prog]

        cmd += [self.pidfile, self.config_file]

        if self.terminal:
            cmd_quoted = []
            for c in cmd:
                c = c.replace('"', r'\"')
                c = f'"{c}"'
                cmd_quoted.append(c)
            subcmd = ' '.join(cmd_quoted)
            cmd = [TERM, '-e', subcmd]

        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        while True:
            with open(self.pidfile, 'r') as fh:
                try:
                    self.pid = int(fh.read())
                    break
                except ValueError:
                    pass

                if p.poll() is not None:
                    cmd = ['rm', self.pidfile]
                    subprocess.run(cmd)
                    raise HostNotStarted(f'{self.hostname} did not start properly.')
                time.sleep(1)

    def add_int(self, intf, host):
        self.int_to_neighbor[intf] = host
        if host in self.neighbor_to_int:
            raise ValueError('Only one link can exist between two hosts')
        self.neighbor_to_int[host] = intf

    def next_int(self):
        int_next = self.next_int_num
        self.next_int_num += 1
        return int_next

    def signal(self, signal_type):
        if self.pid is None:
            return
        cmd = ['sudo', 'kill', f'-{signal_type}', str(self.pid)]
        subprocess.run(cmd, stderr=subprocess.DEVNULL)

    def cleanup(self):
        self.signal('KILL')

        #XXX not sure why this while loop is necessary (i.e., why we need to
        #XXX umount several times)
        while True:
            cmd = ['sudo', 'umount', f'/run/netns/{self.hostname}']
            try:
                subprocess.run(cmd, stderr=subprocess.DEVNULL, check=True)
            except subprocess.CalledProcessError:
                break

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

        if self.pidfile is not None and os.path.exists(self.pidfile):
            cmd = ['sudo', 'rm', self.pidfile]
            subprocess.run(cmd)

        if self.config_file is not None and os.path.exists(self.config_file):
            cmd = ['rm', self.config_file]
            subprocess.run(cmd)

    def label_for_int(self, intf):
        label = ''
        m = re.search(r'\d+$', intf)
        if m is not None:
            label += m.group(0)
        if self.int_to_ip4[intf]:
            if label:
                label += '<BR/>'
            label += '<BR/>'.join(self.int_to_ip4[intf])
        if self.int_to_ip6[intf]:
            if label:
                label += '<BR/>'
            label += '<BR/>\n'.join(self.int_to_ip6[intf])
        return label

class VirtualNetwork(object):
    def __init__(self, native_apps, terminal):
        self.host_by_name = {}
        self.hosts_file = None
        self.native_apps = native_apps
        self.terminal = terminal

    def import_int(self, hostname_addr):
        parts = hostname_addr.split(',')
        hostname = parts[0]
        mac = None
        addrs = parts[1:]
        addrs4 = []
        addrs6 = []
        subnet4 = None
        subnet6 = None
        for addr in addrs:

            # MAC address
            m = MAC_RE.search(addr)
            if m is not None:
                if mac is not None:
                    raise ValueError(f'Only one MAC address is allowed')
                mac = addr
                continue

            # IP address
            slash = addr.find('/')
            if slash < 0:
                raise ValueError(f'Address for {hostname} interface ' + \
                        'must include prefix length!')
            if ':' in addr:
                # IPv6 address
                subnet = str(ipaddress.IPv6Network(addr, strict=False))
                if subnet6 is None:
                    subnet6 = subnet
                if subnet6 != subnet:
                    raise ValueError(f'All connected IP addresses ' + \
                            'must be on the same subnet!')
                addrs6.append(addr)
            else:
                # IPv4 address
                subnet = str(ipaddress.IPv4Network(addr, strict=False))
                if subnet4 is None:
                    subnet4 = subnet
                if subnet4 != subnet:
                    raise ValueError(f'All connected IP addresses ' + \
                            'must be on the same subnet!')
                addrs4.append(addr)

        if hostname not in self.host_by_name:
            self.host_by_name[hostname] = Host(hostname)
        host = self.host_by_name[hostname]
        return host, mac, addrs4, addrs6, subnet4, subnet6

    def import_link(self, line):
        parts = line.split(maxsplit=2)
        if len(parts) < 2 or len(parts) > 3:
            raise ValueError(f'Invalid link format.')

        int1_info, int2_info = parts[:2]
        host1, mac1, addrs41, addrs61, subnet41, subnet61 = \
                self.import_int(int1_info)
        host2, mac2, addrs42, addrs62, subnet42, subnet62 = \
                self.import_int(int2_info)

        if set(addrs41).intersection(set(addrs42)):
            raise ValueError(f'Addresses for {host1.hostname} and ' + \
                    '{host2.hostname} cannot be the same!')
        if subnet41 is not None and subnet42 is not None and \
                subnet41 != subnet42:
            raise ValueError(f'Addresses for {host1.hostname} and ' + \
                    '{host2.hostname} must be in the same subnet!')
        if set(addrs61).intersection(set(addrs62)):
            raise ValueError(f'Addresses for {host1.hostname} and ' + \
                    '{host2.hostname} cannot be the same!')
        if subnet61 is not None and subnet62 is not None and \
                subnet61 != subnet62:
            raise ValueError(f'Addresses for {host1.hostname} and ' + \
                    '{host2.hostname} must be in the same subnet!')

        if len(parts) > 2:
            s = io.StringIO(parts[2])
            csv_reader = csv.reader(s)
            attrs = dict([p.split('=', maxsplit=1) \
                    for p in next(csv_reader)])
        else:
            attrs = {}

        self.add_link(host1, host2, **attrs)
        host1.int_to_mac[host1.neighbor_to_int[host2]] = mac1
        host2.int_to_mac[host2.neighbor_to_int[host1]] = mac2
        host1.int_to_ip4[host1.neighbor_to_int[host2]] = addrs41
        host2.int_to_ip4[host2.neighbor_to_int[host1]] = addrs42
        host1.int_to_ip6[host1.neighbor_to_int[host2]] = addrs61
        host2.int_to_ip6[host2.neighbor_to_int[host1]] = addrs62

    @classmethod
    def from_file(cls, fh, native_apps, terminal):
        net = cls(native_apps, terminal)
        mode = None
        for line in fh:
            line = line.strip()

            if line == 'NODES':
                mode = 'node'
                continue
            elif line == 'LINKS':
                mode = 'link'
                continue
            elif not line:
                continue
            elif line.startswith('#'):
                continue

            if mode == 'node':
                net.import_node(line)
            elif mode == 'link':
                net.import_link(line)
            else:
                pass

        return net

    def import_node(self, line):
        parts = line.split()
        if len(parts) < 1 or len(parts) > 2:
            raise ValueError(f'Invalid node format.')

        hostname = parts[0]
        if len(parts) > 1:
            s = io.StringIO(parts[1])
            csv_reader = csv.reader(s)
            attrs = dict([p.split('=', maxsplit=1) \
                    for p in next(csv_reader)])
        else:
            attrs = {}

        if self.native_apps is not None:
            attrs['native_apps'] = str(self.native_apps)
        if self.terminal is not None:
            attrs['terminal'] = str(self.terminal)

        self.host_by_name[hostname] = Host(hostname, **attrs)

    def add_link(self, host1, host2, bw=None, delay=None, loss=None,
            vlan=None, trunk=False):
        if isinstance(host1, str):
            host1 = self.host_by_name[host1]
        if isinstance(host2, str):
            host2 = self.host_by_name[host2]

        num1 = host1.next_int()
        num2 = host2.next_int()
        int1 = f'{host1.hostname}-{host2.hostname}'
        int2 = f'{host2.hostname}-{host1.hostname}'
        host1.add_int(int1, host2)
        host2.add_int(int2, host1)
        host1.int_to_bw[int1] = bw
        host2.int_to_bw[int2] = bw
        host1.int_to_delay[int1] = delay
        host2.int_to_delay[int2] = delay
        host1.int_to_loss[int1] = loss
        host2.int_to_loss[int2] = loss
        if host1.type == 'switch':
            host1.int_to_vlan[int1] = vlan
        else:
            host1.int_to_vlan[int1] = None
        if host2.type == 'switch':
            host2.int_to_vlan[int2] = vlan
        else:
            host2.int_to_vlan[int2] = None
        if host1.type == 'switch' and host2.type == 'switch':
            host1.int_to_trunk[int1] = trunk
            host2.int_to_trunk[int2] = trunk
        else:
            host1.int_to_trunk[int1] = None
            host2.int_to_trunk[int2] = None

    def apply_links(self):
        done = set()
        for hostname, host in self.host_by_name.items():
            for intf, neighbor in host.int_to_neighbor.items():
                host1 = host
                host2 = neighbor
                int1 = intf
                int2 = host2.neighbor_to_int[host]
                if (host1, host2, int1, int2) in done:
                    continue
                done.add((host1, host2, int1, int2))
                done.add((host2, host1, int2, int1))

                # Sanity check
                if host1.type == 'switch':
                    has_vlans = bool(host1.int_to_vlan[int1] is not None or \
                            host1.int_to_trunk[int1])
                    if has_vlans and host1.has_vlans is False:
                        raise InconsistentConfiguration(f'Some links on {host1.hostname} have VLANs while others do not!')
                    host1.has_vlans = has_vlans
                if host2.type == 'switch':
                    has_vlans = bool(host2.int_to_vlan[int2] is not None or \
                            host2.int_to_trunk[int2])
                    if has_vlans and host2.has_vlans is False:
                        raise InconsistentConfiguration(f'Some links on {host2.hostname} have VLANs while others do not!')
                    host2.has_vlans = has_vlans

                # create both interfaces
                cmd = ['sudo', 'ip', 'link', 'add', int1,
                        'type', 'veth', 'peer', 'name', int2]
                subprocess.run(cmd, check=True)

                host1_bridge = False
                if host1.type == 'switch' and host1.native_apps:
                    host1_bridge = True
                    if not host1.has_bridge:
                        cmd = ['sudo', 'ovs-vsctl', 'add-br',
                                host1.hostname]
                        subprocess.run(cmd, check=True)
                        host1.has_bridge = True

                    cmd = ['sudo', 'ovs-vsctl', 'add-port',
                            host1.hostname, int1]
                    if host1.type == 'switch':
                        if host1.int_to_vlan[int1] is not None:
                            cmd.append(f'tag={host1.int_to_vlan[int1]}')
                        elif host1.int_to_trunk[int1]:
                            pass
                        else:
                            cmd.append('tag=0')
                    subprocess.run(cmd, check=True)

                host2_bridge = False
                if host2.type == 'switch' and host2.native_apps:
                    host2_bridge = True
                    if not host2.has_bridge:
                        cmd = ['sudo', 'ovs-vsctl', 'add-br',
                                host2.hostname]
                        subprocess.run(cmd, check=True)
                        host2.has_bridge = True

                    cmd = ['sudo', 'ovs-vsctl', 'add-port',
                            host2.hostname, int2]
                    if host2.type == 'switch':
                        if host2.int_to_vlan[int2] is not None:
                            cmd.append(f'tag={host2.int_to_vlan[int2]}')
                        elif host2.int_to_trunk[int2]:
                            pass
                        else:
                            cmd.append('tag=0')
                    subprocess.run(cmd, check=True)

                # Move interfaces to their appropriate namespaces
                if host1_bridge:
                    cmd = ['sudo', 'ip', 'link', 'set', int1, 'up']
                    subprocess.run(cmd, check=True)
                else:
                    cmd = ['sudo', 'ip', 'link', 'set', int1, 'netns',
                            host1.hostname]
                    subprocess.run(cmd, check=True)
                if host2_bridge:
                    cmd = ['sudo', 'ip', 'link', 'set', int2, 'up']
                    subprocess.run(cmd, check=True)
                else:
                    cmd = ['sudo', 'ip', 'link', 'set', int2, 'netns',
                            host2.hostname]
                    subprocess.run(cmd, check=True)


    def create_hosts_file(self):
        cmd = ['mkdir', '-p', TMPDIR]
        subprocess.run(cmd)
        fd, self.hosts_file = tempfile.mkstemp(prefix=f'hosts-', dir=TMPDIR)

        with os.fdopen(fd, 'w') as fh:
            fh.write('127.0.0.1 localhost\n')

            for hostname, host in self.host_by_name.items():
                host.create_hosts_file_entries(fh)

    def config(self):
        cmd = ['mkdir', '-p', TMPDIR]
        subprocess.run(cmd)
        fd, self.commsock_file = tempfile.mkstemp(suffix='.sock', dir=TMPDIR)
        os.close(fd)
        subprocess.run(['rm', self.commsock_file])
        self.commsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        self.commsock.bind(self.commsock_file)

        self.create_hosts_file()
        for hostname, host in self.host_by_name.items():
            host.create_config()

    def signal_hosts(self, signal):
        for hostname, host in self.host_by_name.items():
            host.signal(signal)

    def wait_for_startup(self):
        while True:
            none_exists = True
            for hostname, host in self.host_by_name.items():
                if os.path.exists(host.pidfile):
                    pid = open(host.pidfile, 'r').read()
                    cmd = ['ps', '-p', pid]
                    p = subprocess.run(cmd, stdout=subprocess.DEVNULL)
                    if p.returncode != 0:
                        cmd = ['rm', host.pidfile]
                        subprocess.run(cmd)
                        raise HostNotStarted(f'{hostname} did not start properly.')
                    none_exists = False
            if none_exists:
                break
            time.sleep(1)

    def start(self, wireshark_host=None):
        for hostname, host in self.host_by_name.items():
            host.start(self.hosts_file, self.commsock_file)

        self.apply_links()
        self.signal_hosts('HUP')
        self.wait_for_startup()
        if wireshark_host is not None:
            self.start_wireshark(self.host_by_name[wireshark_host])
        self.signal_hosts('HUP')

    def cleanup(self):
        for hostname, host in self.host_by_name.items():
            host.cleanup()

        cmd = ['rm', self.hosts_file]
        subprocess.run(cmd)

        self.commsock.close()
        cmd = ['rm', self.commsock_file]
        subprocess.run(cmd)

    def display(self, to_screen, output_file):
        try:
            from pygraphviz import AGraph
        except ImportError:
            sys.stderr.write('Pygraphviz is not installed, ' + \
                    'so the network cannot be displayed\n')
            return

        G = AGraph()

        done = set()
        for hostname, host in self.host_by_name.items():
            for intf, neighbor in host.int_to_neighbor.items():
                host1 = host
                host2 = neighbor
                int1 = intf
                int2 = host2.neighbor_to_int[host]
                if (host1, host2, int1, int2) in done:
                    continue
                done.add((host1, host2, int1, int2))
                done.add((host2, host1, int2, int1))
                G.add_edge(host1.hostname, host2.hostname,
                        headlabel=f'<{host1.label_for_int(int1)}>',
                        taillabel=f'<{host2.label_for_int(int2)}>')
        img = G.draw(prog='dot')
        if to_screen:
            subprocess.run(['graph-easy', '--from', 'graphviz'], input=img,
                    stderr=subprocess.DEVNULL)
        if output_file:
            G.draw(output_file, format='png', prog='dot')

    def start_wireshark(self, host):
        if host.type == 'switch' and host.native_apps:
            cmd = ['sudo', 'wireshark']
        else:
            cmd = ['sudo', '-E', 'ip', 'netns', 'exec', host.hostname, 'wireshark']
        subprocess.Popen(cmd)

    def message_loop(self):
        start_time = time.time()
        while True:
            data, peer = self.commsock.recvfrom(4096)
            data = data.decode('utf-8')
            try:
                hostname, msg = data.split(',', maxsplit=1)
            except ValueError:
                hostname = ''
                msg = data
            ts = time.time() - start_time
            print('%000.3f \033[1m%4s\033[0m  %s' % (ts, hostname, msg))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wireshark', '-w',
            action='store', type=str, default=None,
            metavar='NODE',
            help='Start wireshark for the specified node')
    parser.add_argument('--display',
            action='store_const', const=True, default=False,
            help='Display the network configuration as text')
    parser.add_argument('--terminal',
            action='store', type=str, choices=('all', 'none'), default=None,
            help='Specify that all virtual hosts should launch (all) or not launch (none) a terminal.') 
    parser.add_argument('--native-apps',
            action='store', type=str, choices=('all', 'none'), default=None,
            help='Specify that all virtual hosts should enable (all) or disable (none) native apps.') 
    parser.add_argument('--display-file',
            type=argparse.FileType('wb'), action='store',
            help='Print the network configuration to a file (.png)')
    parser.add_argument('config_file',
            type=argparse.FileType('r'), action='store',
            help='File containing the network configuration')
    args = parser.parse_args(sys.argv[1:])

    if args.native_apps == 'all':
        native_apps = True
    elif args.native_apps == 'none':
        native_apps = False
    else:
        native_apps = None

    if args.terminal == 'all':
        terminal = True
    elif args.terminal == 'none':
        terminal = False
    else:
        terminal = None

    net = VirtualNetwork.from_file(args.config_file, native_apps, terminal)

    if args.wireshark is not None and \
            args.wireshark not in net.host_by_name:
        sys.stderr.write(f'The host specified for wireshark ' + \
                f'({args.wireshark}) does not exist.\n')
        sys.exit(1)

    if args.display or args.display_file is not None:
        net.display(args.display, args.display_file)

    try:
        net.config()
        net.start(args.wireshark)
        sys.stdout.write('Ctrl-c to quit\n')
        net.message_loop()
    except KeyboardInterrupt:
        pass
    finally:
        net.cleanup()

if __name__ == '__main__':
    main()
