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

import socket

from cougarnet import util

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
            except (FileNotFoundError, ConnectionRefusedError):
                # other side has not connected yet
                pass

def send_user_to_raw(helper_sock_raw, raw_sock):
    while True:
        try:
            frame = helper_sock_raw.recv(4096)
        except BlockingIOError:
            return
        raw_sock.send(frame)
