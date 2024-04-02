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
Functions called by virtual hosts to initialize them for use in part of a
virtual network.
'''

import json
import os
import socket

def main():
    '''Set up communication with the coordinating proces over a socket, send a
    signal indicating that we're "up", and wait for the signal from the
    coordinating process to indicate that we can continue.'''

    comm_sock_paths = json.loads(os.environ['COUGARNET_COMM_SOCK'])

    comm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
    comm_sock.bind(comm_sock_paths['local'])
    comm_sock.connect(comm_sock_paths['remote'])

    # tell the coordinating process that everything is ready to go
    comm_sock.send(b'\x00')
    # wait for the coordinating process to indicate that it can proceed
    comm_sock.recv(1)

    # close socket and remove the associated file
    comm_sock.close()
    os.unlink(comm_sock_paths['local'])

if __name__ == '__main__':
    main()
