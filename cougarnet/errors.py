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

'''Various errors related to Cougarnet.'''

class CougarnetError(Exception):
    '''Base class for errors related to Cougarnet.'''

class SysCmdError(CougarnetError):
    '''An error raised when there was an error running a privileged command
    using SysCmdHelper.'''

class CommandPrereqError(SysCmdError):
    '''An error raised when a command was unable to be run because a prequisite
    was missing.'''

class CommandExecError(SysCmdError):
    '''An error raised when a command was executed and resulted in a non-zero
    exit code.'''

class ConfigurationError(CougarnetError):
    '''An error raised when there was an error with content in the Cougarnet
    configuration file.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lineno = 0

class StartupError(CougarnetError):
    '''An error raised when there was an error with starting up a Cougarnet
    configuration.'''
