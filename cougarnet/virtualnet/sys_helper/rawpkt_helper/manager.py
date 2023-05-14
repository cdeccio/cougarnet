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

'''A class for creating and managing a process that captures packets from a raw
socket and sends them to a UNIX domain socket, and vice-versa.'''

import os

from cougarnet.virtualnet.sys_helper.manager import \
        SysHelperManager, LIBEXEC_DIR

RAWPKT_HELPER_SCRIPT = os.path.join(LIBEXEC_DIR, 'rawpkt_helper')

class RawPktHelperManager(SysHelperManager):
    '''A class for creating and managing a process that captures packets from a
    raw socket and sends them to a UNIX domain socket, and vice-versa.'''

    def __init__(self, pid, *ints):
        super().__init__('nsenter', '--target', str(pid), '--all',
                RAWPKT_HELPER_SCRIPT, *ints)
