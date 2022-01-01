import asyncio
import ctypes
import os
import re
import socket
import subprocess

IP_ADDR_MTU_RE = re.compile(r'^\d:\s+.*\smtu\s+(\d+)(\s|$)')
IP_ADDR_MAC_RE = re.compile(r'^\s+link/ether\s+([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})(\s|$)')
IP_ADDR_IPV4_RE = re.compile(r'^\s+inet\s+([0-9]{1,3}(\.[0-9]{1,3}){3})\/(\d{1,2})\s+brd\s+([0-9]{1,3}(\.[0-9]{1,3}){3})(\s|$)')
IP_ADDR_IPV6_RE = re.compile(r'^\s+inet6\s+([0-9a-f:]+)\/(\d{1,3})\s.*scope\s+(link|global)(\s|$)')

# From /usr/include/linux/if_ether.h
ETH_P_ALL = 0x0003
ETH_P_8021Q = 0x8100

# From /usr/include/x86_64-linux-gnu/bits/socket.h:
SOL_PACKET = 263

# /usr/include/linux/if_packet.h
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4 # auxdata has valid tp_vlan_tci

class tpacket_auxdata(ctypes.Structure):
    _fields_ = [
        ("tp_status", ctypes.c_uint),
        ("tp_len", ctypes.c_uint),
        ("tp_snaplen", ctypes.c_uint),
        ("tp_mac", ctypes.c_ushort),
        ("tp_net", ctypes.c_ushort),
        ("tp_vlan_tci", ctypes.c_ushort),
        ("tp_padding", ctypes.c_ushort),
    ]

class InterfaceInfo:
    def __init__(self, macaddr, ipv4addrs, ipv4prefix, ipv4broadcast, \
            ipv6addrs, ipv6lladdr, ipv6prefix, mtu):
        self.macaddr = macaddr
        self.ipv4addrs = ipv4addrs
        self.ipv4prefix = ipv4prefix
        self.ipv4broadcast = ipv4broadcast
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
        self.comm_sock.bind((os.environ['COUGARNET_MY_SOCK']))
        self.hostname = socket.gethostname()
        self._setup_send_sockets()
        self._setup_receive_sockets()
        self._set_interface_info()

    def __del__(self):
        try:
            os.unlink(os.environ['COUGARNET_MY_SOCK'])
        except FileNotFoundError:
            pass

    def _setup_receive_sockets(self):
        loop = asyncio.get_event_loop()
        ints = os.listdir('/sys/class/net/')
        for intf in ints:

            #XXX this is a hack. fix this by putting it in its own namespace
            #if intf.startswith('lo'):
            #    continue
            if not intf.startswith(f'{self.hostname}-'):
                continue

            # For receiving...
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((intf, 0))
            sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)

            sock.setblocking(False)
            loop.add_reader(sock, self._handle_incoming_data, sock, intf)

    def _setup_send_sockets(self):
        ints = os.listdir('/sys/class/net/')
        for intf in ints:
            #XXX this is a hack. fix this by putting it in its own namespace
            #if intf.startswith('lo'):
            #    continue
            if not intf.startswith(f'{self.hostname}-'):
                continue

            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((intf, 0))
            self.int_to_sock[intf] = sock

    @classmethod
    def _get_interface_info(cls, intf):
        macaddr = None
        mtu = None
        ipv4prefix = None
        ipv4broadcast = None
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
                ipv4prefix = int(m.group(3))
                ipv4broadcast = m.group(4)
                continue

            m = IP_ADDR_IPV6_RE.match(line)
            if m is not None:
                # IPv6 address
                if m.group(3) == 'global':
                    # IPv6 global address
                    ipv6addrs.append(m.group(1))
                    ipv6prefix = int(m.group(2))
                elif m.group(3) == 'link':
                    # IPv6 link-local address
                    ipv6lladdr = m.group(1)
                continue

            m = IP_ADDR_MTU_RE.match(line)
            if m is not None:
                mtu = int(m.group(1))

        return InterfaceInfo(macaddr, ipv4addrs, ipv4prefix, ipv4broadcast,
                        ipv6addrs, ipv6lladdr, ipv6prefix, mtu)

    def _handle_frame(self, frame, intf):
        pass

    def _handle_incoming_data(self, sock, intf):
        while True:
            try:
                frame, info = self._recv_raw(sock, 4096)
            except BlockingIOError:
                return
            (ifname, proto, pkttype, hatype, addr) = info
            if pkttype == socket.PACKET_OUTGOING:
                continue
            self._handle_frame(frame, intf)

    def _recv_raw(self, sock, bufsize):
        """Internal function to receive a Packet,
        and process ancillary data.

        From: https://github.com/secdev/scapy/pull/2091/files
        """

        flags_len = socket.CMSG_LEN(4096)
        pkt, ancdata, flags, sa_ll = sock.recvmsg(bufsize, flags_len)

        if not pkt:
            return pkt, sa_ll

        for cmsg_lvl, cmsg_type, cmsg_data in ancdata:
            # Check available ancillary data
            if (cmsg_lvl == SOL_PACKET and cmsg_type == PACKET_AUXDATA):
                # Parse AUXDATA
                auxdata = tpacket_auxdata.from_buffer_copy(cmsg_data)
                if auxdata.tp_vlan_tci != 0 or \
                        auxdata.tp_status & TP_STATUS_VLAN_VALID:
                    # Insert VLAN tag
                    tag = struct.pack(
                        "!HH",
                        ETH_P_8021Q,
                        auxdata.tp_vlan_tci
                    )
                    pkt = pkt[:12] + tag + pkt[12:]
        return pkt, sa_ll

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
        self.comm_sock.send(msg.encode('utf-8'))
