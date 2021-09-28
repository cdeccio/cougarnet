import os
import re
import socket
import subprocess

#From /usr/include/linux/if_ether.h:
ETH_P_ALL = 0x0003

IP_ADDR_MTU_RE = re.compile(r'^\d:\s+.*\smtu\s+(\d+)(\s|$)')
IP_ADDR_MAC_RE = re.compile(r'^\s+link/ether\s+([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})(\s|$)')
IP_ADDR_IPV4_RE = re.compile(r'^\s+inet\s+([0-9]{1,3}(\.[0-9]{1,3}){3})\/(\d{1,2})(\s|$)')
IP_ADDR_IPV6_RE = re.compile(r'^\s+inet6\s+([0-9a-f:]+)\/(\d{1,3})\s.*scope\s+(link|global)(\s|$)')

class InterfaceInfo:
    def __init__(self, macaddr, ipv4addrs, ipv4prefix, \
            ipv6addrs, ipv6lladdr, ipv6prefix, mtu):
        self.macaddr = macaddr
        self.ipv4addrs = ipv4addrs
        self.ipv4prefix = ipv4prefix
        self.ipv6addrs = ipv6addrs
        self.ipv6lladdr = ipv6lladdr
        self.ipv6prefix = ipv6prefix
        self.mtu = mtu

class BaseFrameHandler:
    def __init__(self):
        self.int_to_sock = {}
        self.int_to_info = {}
        self.comm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        self.comm_sock.connect(os.environ['COUGARNET_COMM_SOCK'])
        self.hostname = socket.gethostname()
        self._setup_send_sockets()
        self._set_interface_info()

    def _setup_send_sockets(self):
        ints = os.listdir('/sys/class/net/')
        for intf in ints:
            if intf.startswith('lo'):
                continue

            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((intf, 0))
            self.int_to_sock[intf] = sock

    @classmethod
    def _get_interface_info(cls, intf):
        macaddr = None
        mtu = None
        ipv4prefix = None
        ipv4addrs = []
        ipv6prefix = None
        ipv6addrs = []
        ipv6lladdr = None
        output = subprocess.run(['ip', 'addr', 'show', intf], \
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
        output = output.decode('utf-8')
        for line in output.splitlines():
            m = IP_ADDR_MAC_RE.match(line)
            if m is not None:
                # MAC address
                macaddr = m.group(1)
                continue

            m = IP_ADDR_IPV4_RE.match(line)
            if m is not None:
                # IPv4 address
                ipv4addrs.append(m.group(1))
                ipv4prefix = m.group(3)
                continue

            m = IP_ADDR_IPV6_RE.match(line)
            if m is not None:
                # IPv6 address
                if m.group(3) == 'global':
                    # IPv6 global address
                    ipv6addrs.append(m.group(1))
                    ipv6prefix = m.group(2)
                elif m.group(3) == 'link':
                    # IPv6 link-local address
                    ipv6lladdr = m.group(1)
                continue

            m = IP_ADDR_MTU_RE.match(line)
            if m is not None:
                mtu = m.group(1)

        return InterfaceInfo(macaddr, ipv4addrs, ipv4prefix,
                        ipv6addrs, ipv6lladdr, ipv6prefix, mtu)

    def _set_interface_info(self):
        for intf in self.int_to_sock:
            self.int_to_info[intf] = self._get_interface_info(intf)

    def get_first_interface(self):
        try:
            return [i for i in self.int_to_sock][0]
        except IndexError:
            return None

    def send_frame(self, frame, intf):
        self.int_to_sock[intf].send(frame)

    def log(self, msg):
        self.comm_sock.send(f'{self.hostname},{msg}'.encode('utf-8'))
