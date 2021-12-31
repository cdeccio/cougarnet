#!/usr/bin/env python3

from setuptools import setup

setup(name='cougarnet',
        version='0.0.0',
        author='Casey Deccio',
        author_email='casey@deccio.net',
        url='https://github.com/cdeccio/cougarnet/',
        description='Network virtualization tool suite for Linux',
        license='LICENSE',
        packages=['cougarnet', 'cougarnet/virtualnet', 'cougarnet/sim'],
        scripts=['bin/cougarnet'],
        data_files=[('share/doc/cougarnet', ['README.md'])],
        classifiers=[],
        cmdclass={},
)
