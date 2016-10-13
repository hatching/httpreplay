#!/usr/bin/env python
# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

from setuptools import setup

setup(
    name="HTTPReplay",
    version="0.1.17",
    author="Jurriaan Bremer",
    author_email="jbr@cuckoo.sh",
    packages=[
        "httpreplay",
    ],
    license="GPLv3",
    description="Properly interpret, decrypt, and replay pcap files",
    install_requires=[
        "dpkt==1.8.7",
        "tlslite-ng==0.6.0a3",
        "click>=6.6, <7",
    ],
    extras_require={
        "mitmproxy": [
            "mitmproxy>=0.17",
        ],
        "dev": [
            "pytest>=2.9.1"
        ]
    },
    entry_points={
        "console_scripts": [
            "httpreplay = httpreplay.main:httpreplay",
            "pcap2mitm = httpreplay.main:pcap2mitm",
        ]
    },
)
