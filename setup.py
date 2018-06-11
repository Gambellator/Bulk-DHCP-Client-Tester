# -*- coding: utf-8 -*-
#

from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='bulkdhcpclient',
    version='0.0.1',
    description='Bulk DHCP client tester',
    long_description=readme,
    author='Gambellator',
    author_email='andrew@gambell.io',
    url='https://github.com/Gambellator/Bulk-DHCP-Client-Tester',
    license=license,
    packages=find_packages(exclude=('samples'))
)
