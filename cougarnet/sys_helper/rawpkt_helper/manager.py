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

from cougarnet.globals import LIBEXEC_DIR
from cougarnet.sys_helper.manager import SysHelperManager

RAWPKT_HELPER_SCRIPT = os.path.join(LIBEXEC_DIR, 'rawpkt_helper')


class RawPktHelperManager(SysHelperManager):
    '''A class for creating and managing a process that captures packets from a
    raw socket and sends them to a UNIX domain socket, and vice-versa.'''

    def __init__(self, pid, *ints):
        cmd = ['nsenter', '--target', str(pid), '--all',
               RAWPKT_HELPER_SCRIPT]
        dir1, dir2, new_ints = self.consolidate_dirs(ints)
        if dir1 and dir2:
            # Use the --raw-sock-directory and --user-sock-directory options to
            # shorten the length of the command-line arguments.  If there is a
            # common directory across all raw socket paths and a common
            # directory across all raw socket paths, consolidate_dirs() will
            # find those common directories, use them as command-line options,
            # and then use only the relativized paths.
            cmd += ['--raw-sock-directory', dir1,
                    '--user-sock-directory', dir2]
            cmd += new_ints
        else:
            cmd += ints

        super().__init__(*cmd)

    @classmethod
    def consolidate_dirs(cls, ints):
        '''
        Search through the list of interface mappings.  Each mapping has the
        form int=path1:path2, where path1 is the path to the socket used by the
        helper (i.e., "raw"), and path2 is the path to the socket used by the
        user application (i.e., "user").   If all interface mappings are
        well-formed, all paths are absoluate, all raw socket paths have a
        common directory, and all user paths share a common directory, then
        remove the common directory from the raw socket paths and the common
        directory from the user socket paths.  Return a tuple consisting of the
        common directories and the newly relativized paths.  Examples are given
        below.  This is all to minimize the size of the command-line arguments.

        >>> RawPktHelperManager.consolidate_dirs(['foo'])
        (None, None, ['foo'])
        >>> RawPktHelperManager.consolidate_dirs(['foo=bar'])
        (None, None, ['foo=bar'])
        >>> RawPktHelperManager.consolidate_dirs(['foo=bar/bar1:baz/baz1'])
        (None, None, ['foo=bar/bar1:baz/baz1'])
        >>> RawPktHelperManager.consolidate_dirs(['foo=/bar/bar1:baz/baz1'])
        (None, None, ['foo=/bar/bar1:baz/baz1'])
        >>> RawPktHelperManager.consolidate_dirs(['foo=bar/bar1:/baz/baz1'])
        (None, None, ['foo=bar/bar1:/baz/baz1'])
        >>> RawPktHelperManager.consolidate_dirs(['foo=/bar/bar1:/baz/baz1',
        ...     'foo1=/bar2/bar1:/baz/baz1'])
        (None, None, ['foo=/bar/bar1:/baz/baz1', 'foo1=/bar2/bar1:/baz/baz1'])
        >>> RawPktHelperManager.consolidate_dirs(['foo=/bar/bar1:/baz/baz1',
        ...     'foo1=bar1:baz1'])
        (None, None, ['foo=/bar/bar1:/baz/baz1', 'foo1=bar1:baz1'])
        >>> RawPktHelperManager.consolidate_dirs(['foo=/bar/bar1:/baz/baz1',
        ...     'foo1=/bar/bar1:/baz/baz1'])
        ('/bar', '/baz', ['foo=bar1:baz1', 'foo1=bar1:baz1'])
        '''

        dir1_set = set()
        dir2_set = set()

        new_ints = []
        for p in ints:
            try:
                intf, paths = p.split('=')
            except ValueError:
                return None, None, ints

            try:
                path1, path2 = paths.split(':')
            except ValueError:
                return None, None, ints

            if not os.path.isabs(path1) or \
                    not os.path.isabs(path2):
                return None, None, ints

            dir1, file1 = os.path.split(path1)
            dir1_set.add(dir1)

            dir2, file2 = os.path.split(path2)
            dir2_set.add(dir2)

            new_ints.append(f'{intf}={file1}:{file2}')

        if len(dir1_set) == 1 and len(dir2_set) == 1:
            return dir1_set.pop(), dir2_set.pop(), new_ints
        else:
            return None, None, ints
