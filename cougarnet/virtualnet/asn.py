# This file is a part of Cougarnet, a tool for creating virtual networks.
#
# Copyright 2021-2025 Casey Deccio (casey@deccio.net)
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

'''Classes and functions for maintaining configurations for autonomous
systems.'''

import ipaddress

from cougarnet.errors import ConfigurationError

class ASNConfig:
    '''The configuration for an autonomus system number (ASN).'''

    attrs = { 'type': 'stub',
            'prefixes': None,
            }

    def __init__(self, asn, instance, **kwargs):

        self.asn = asn
        self.instance = instance
        self.routers = []

        for attr in self.__class__.attrs:
            setattr(self, attr, kwargs.get(attr, self.__class__.attrs[attr]))

        prefixes = []
        if self.prefixes is not None:
            for prefix in self.prefixes.split(';'):
                try:
                    prefixes.append(ipaddress.ip_network(prefix))
                except ValueError:
                    raise ConfigurationError(f'Invalid IP prefix: {prefix}')
        self.prefixes = prefixes

    def __eq__(self, other):
        if other is None:
            return False
        return self.asn == other.asn

    def add_router(self, router):
        self.routers.append(router)
