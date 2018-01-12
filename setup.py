#!/usr/bin/python

import os
import setuptools


def package_resources(path):
    paths = []
    for path, directories, files in os.walk(path):
        for filename in files:
            paths.append(os.path.join('..', path, filename))
    return paths


setuptools.setup(
    name = 'adpasswd',
    version = '1.0.0',
    packages = [
        'adpasswd',
    ],
    package_data = {
        'adpasswd': package_resources('adpasswd/icons'),
    },
    entry_points = {
        'console_scripts': [
            'adpasswd=adpasswd.entry:entry'
        ],
    },
)

# vi: ts=4 et:
