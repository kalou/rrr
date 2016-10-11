import sys
import os
import re

from setuptools import setup, find_packages

requires = [
    'flask',
    'requests',
    'dnsknife>=0.10',
    'pyyaml',
    'pysocks'
]

setup(
    name="rrr",
    version='0.0.3',
    packages=find_packages(),
    description="an implementation of draft-ietf-regext-dnsoperator-to-rrr-protocol-01",
    install_requires=requires,
)

