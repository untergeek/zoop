#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Zabbix Object Oriented Python
"""
import os
from setuptools import setup, find_packages, findall


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name='zoop',
    url='https://github.com/untergeek/zoop',
    version='0.1',
    license='Apache 2.0',
    author='Aaron Mildenstein',
    author_email='aaron@mildensteins.com',
    description='Zabbix Object Oriented Python',
    long_description=read('README.md'),
    py_modules=['zoop'],
    include_package_data=True,
    zip_safe=False,
    platforms='any',
)
