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
        packages=['cougarnet', 'cougarnet/virtualnet', 'cougarnet/sim',
            'cougarnet/sys_helper'],
        scripts=['bin/cougarnet'],
        data_files=[('share/doc/cougarnet', ['README.md']),
            (os.path.join(sys.prefix, 'libexec', 'cougarnet'),
                ('libexec/syscmd_helper', 'libexec/rawpkt_helper'))
            ],
        classifiers=[],
        cmdclass={},
)
