#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

from setuptools import setup


requirements = [
    "q",
    "pyyaml",
    "simplejson",
    "tabulate",
    "vivisect",
    "plugnplay",
    "viv-utils",
    "enum34"
]

setup(
    name='floss',
    version='1.6.1',
    description="FireEye Labs Obfuscated String Solver",
    author="Willi Ballenthin, Moritz Raabe",
    author_email='william.ballenthin@mandiant.com, moritz.raabe@mandiant.com',
    url='https://www.github.com/fireeye/flare-floss',
    packages=[
        'floss',
        'floss.plugins',
    ],
    package_dir={'floss': 'floss'},
    entry_points={
        "console_scripts": [
            "floss=floss.main:main",
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    zip_safe=False,
    keywords='floss',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
    ],
)
