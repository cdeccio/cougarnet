#!/usr/bin/env python3

import os
import sys

from setuptools import setup

setup(name='cougarnet',
        version='0.0.0',
        author='Casey Deccio',
        author_email='casey@deccio.net',
        url='https://github.com/cdeccio/cougarnet/',
        description='Network virtualization tool suite for Linux',
        license='LICENSE',
        packages=['cougarnet', 'cougarnet/sim', 'cougarnet/virtualnet',
            'cougarnet/sys_helper',
            'cougarnet/sys_helper/cmd_helper',
            'cougarnet/sys_helper/rawpkt_helper'],
        scripts=['bin/cougarnet'],
        data_files=[('share/doc/cougarnet', ['README.md']),
                    ('libexec/cougarnet',
                     ('libexec/syscmd_helper', 'libexec/rawpkt_helper'))
            ],
        classifiers=[],
        cmdclass={},
)
