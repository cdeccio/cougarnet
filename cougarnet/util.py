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

'''
Various utility functions for Cougarnet.
'''

import binascii
import ctypes
import os
import re
import signal
import socket
import subprocess
import struct
import sys
import time

# From /usr/include/linux/if_ether.h
ETH_P_ALL = 0x0003
ETH_P_8021Q = 0x8100

# From /usr/include/x86_64-linux-gnu/bits/socket.h:
SOL_PACKET = 263

# /usr/include/linux/if_packet.h
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4 # auxdata has valid tp_vlan_tci

HOST_RE = re.compile(r'^[a-z]([a-z0-9-]*[a-z0-9])?$')

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

def raise_interrupt(signum, frame):
    raise KeyboardInterrupt()

def mac_str_to_binary(mac_str):
    '''Given a MAC address in presentation format as a string, return the
    equivalent bytes object.'''

    return binascii.unhexlify(mac_str.replace(':', ''))

def mac_binary_to_str(mac_bin):
    '''Given a bytes object, return the equivalent MAC address in presentation
    format as a string.'''

    return ':'.join(['%02x' % b for b in mac_bin])

def ip_str_to_binary(ip_str):
    '''Given an IPv4 or IPv6 address in presentation format as a string, return
    the equivalent bytes object.'''

    if ':' in ip_str:
        af = socket.AF_INET6
    else:
        af = socket.AF_INET
    return socket.inet_pton(af, ip_str)

def ip_binary_to_str(ip_bin):
    '''Given a bytes object, return the equivalent IPv4 or IPv6 address in
    presentation format as a string.'''

    if len(ip_bin) > 4:
        af = socket.AF_INET6
    else:
        af = socket.AF_INET
    return socket.inet_ntop(af, ip_bin)

def pid_is_running(pid):
    '''Return True if the process associated with a given pid (int) is running;
    False otherwise.'''

    cmd = ['ps', '-p', str(pid)]
    p = subprocess.run(cmd, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return p.returncode == 0

def is_valid_hostname(hostname):
    '''Return True  if a string begins with a letter, ends with a letter or
    number, and is composed of only lower-case letters, numbers, and
    hyphens.'''

    if not hostname[0].isalpha():
        return False
    if HOST_RE.search(hostname) is None:
        return False
    return True

def kill(pid, sig):
    '''Send a signal (e.g., TERM, KILL) to a process.  If a permissions error
    is detected, and elevate_if_needed is True, then send the same signal again
    as root.  Return True if the signal was sent successfully; False
    otherwise.'''

    cmd = ['kill', f'-{sig}', str(pid)]
    p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, check=False)
    #if p.returncode != 0:
    #    stderr = p.stderr.decode('utf-8').lower()
    #    #XXX this does not work for non-English
    #    if 'not permitted' in stderr and elevate_if_needed:
    #        cmd.insert(0, 'sudo')
    #        p = subprocess.run(cmd, check=False,
    #                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode == 0

def kill_until_terminated(pid):
    '''Send TERM to a process.  If the process continues to run, then send
    KILL.  In both cases, elevate if a permissions error is detected, and
    elevate_if_needed is True.'''

    sigs = ('TERM', 'KILL')
    for sig in sigs:
        kill(pid, sig)
        if pid_is_running(pid):
            time.sleep(0.2)
        if pid_is_running(pid):
            continue
        break

def recv_raw(sock, bufsize):
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

def start_helper(cmd):
    # We use two pipes: one for letting the helper know that the cougarnet
    # process has died, so it can terminate as well; and one for the helper
    # to communicate back to the cougarnet process that it is up and
    # running.  The second pipe will be closed once the "alive" message has
    # been received.
    readfd, writefd = os.pipe()
    alive_readfd, alive_writefd = os.pipe()
    pid = os.fork()

    if pid == 0:
        # This is the child process, which will become the helper process
        # through the use of exec, once it is properly prepared.

        # Close the ends of the pipe that will not be used by this process.
        os.close(writefd)
        os.close(alive_readfd)

        # Duplicate readfd on stdin
        os.dup2(readfd, sys.stdin.fileno())
        os.close(readfd)

        # Duplicate alive_writefd on stdout
        os.dup2(alive_writefd, sys.stdout.fileno())
        os.close(alive_writefd)

        os.execvp(cmd[0], cmd)
        sys.exit(1)

    # Close the ends of the pipe that will not be used by this process.
    os.close(readfd)
    os.close(alive_writefd)

    # Use ALRM to let us know when we've waited too long for the child
    # process to become ready.
    old_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, raise_interrupt)
    signal.alarm(3)
    try:
        if len(os.read(alive_readfd, 1)) < 1:
            # read resulted in error
            kill_until_terminated(pid)
            return False
    except KeyboardInterrupt:
        # Timeout (ALRM signal was received)
        kill_until_terminated(pid)
        return False
    finally:
        # Reset alarm, restore previous ALRM handler, and close
        # alive_readfd, which is no longer needed.
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
        os.close(alive_readfd)
    return True
