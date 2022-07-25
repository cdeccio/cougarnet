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

import argparse
import asyncio
import atexit
import os
import socket
import subprocess
import sys

from cougarnet import util


# From /usr/include/linux/if_ether.h
ETH_P_ALL = 0x0003

def _delete_softly(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

def _raise():
    raise KeyboardInterrupt 

def send_raw_to_user(raw_sock, helper_sock_raw, dst_sock):
    while True:
        try:
            frame, info = util.recv_raw(raw_sock, 4096)
        except BlockingIOError:
            return
        (ifname, proto, pkttype, hatype, addr) = info
        if pkttype != socket.PACKET_OUTGOING:
            try:
                helper_sock_raw.sendto(frame, dst_sock)
            except FileNotFoundError:
                # other side has not connected yet
                pass

def send_user_to_raw(helper_sock_raw, raw_sock):
    while True:
        try:
            frame = helper_sock_raw.recv(4096)
        except BlockingIOError:
            return
        raw_sock.send(frame)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', '-u',
            action='store', type=str,
            help='User that should own the sockets')
    parser.add_argument('int_sock_mapping',
            action='store', type=str, nargs='+',
            help='Interface-to-socket mapping ' + \
                    '(int=sock:sock[,int=sock:sock,...])')

    args = parser.parse_args(sys.argv[1:])

    loop = asyncio.get_event_loop()

    loop.add_reader(sys.stdin, _raise)

    sockets = {}
    ints_available = set(os.listdir('/sys/class/net/'))
    for p in args.int_sock_mapping:
        try:
            intf, paths = p.split('=')
        except ValueError:
            sys.stderr.write(f'Invalid mapping: {p}\n')
            sys.exit(1)

        try:
            helper_sock_raw_path, helper_sock_user_path = paths.split(':')
        except ValueError:
            sys.stderr.write(f'Invalid mapping: {p}\n')
            sys.exit(1)

        if intf not in ints_available:
            sys.stderr.write(f'Invalid interface: {intf}\n')
            sys.exit(1)

        helper_sock_raw = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            helper_sock_raw.bind(helper_sock_raw_path)
        except OSError as e:
            sys.stderr.write(f'Invalid path: {helper_sock_raw_path} ({str(e)})\n')
            sys.exit(1)
        atexit.register(_delete_softly, helper_sock_raw_path)
        if args.user is not None:
            subprocess.run(['chown', args.user, helper_sock_raw_path], check=True)
  
        #try:
        #    helper_sock_raw.connect(helper_sock_user_path)
        #except OSError as e:
        #    sys.stderr.write(f'Invalid path (2): {helper_sock_user_path} ({str(e)})\n')
        #    sys.exit(1)
        atexit.register(_delete_softly, helper_sock_user_path)
        #if args.user is not None:
        #    subprocess.run(['chown', args.user, helper_sock_user_path], check=True)

        helper_sock_raw.setblocking(False)

        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        raw_sock.bind((intf, 0))
        raw_sock.setblocking(False)

        loop.add_reader(raw_sock, send_raw_to_user, raw_sock,
                helper_sock_raw, helper_sock_user_path)
        loop.add_reader(helper_sock_raw, send_user_to_raw,
                helper_sock_raw, raw_sock)

    sys.stdout.buffer.write(b'\x00')
    sys.stdout.close()

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()

if __name__ == '__main__':
    main()
