# Copyright (C) 2017 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import dpkt.pcap
import io
import os
import pytest
import struct

from httpreplay.exceptions import (
    UnknownEthernetProtocol, UnknownIpProtocol, UnknownDatalink
)
from httpreplay.reader import PcapReader

def test_unknownDatalinkException():
    r = PcapReader(io.BytesIO(
        struct.pack(
            "IHHIIII", dpkt.pcap.TCPDUMP_MAGIC, dpkt.pcap.PCAP_VERSION_MAJOR,
            dpkt.pcap.PCAP_VERSION_MINOR, 0, 0, 1500, 0
        ) + b"A"*16
    ))
    with pytest.raises(UnknownDatalink):
        list(r.process())

def test_unknownEthernetProtocolException():
    r = PcapReader(open(
        os.path.join("tests", "pcaps", "unknownEthernet.pcap"), "rb"
    ))
    with pytest.raises(UnknownEthernetProtocol):
        list(r.process())

def test_unknownIpProtocolException():
    r = PcapReader(open(
        os.path.join("tests", "pcaps", "unknownIpProtocol.pcap"), "rb"
    ))
    with pytest.raises(UnknownIpProtocol):
        list(r.process())

class PcapTest(object):
    pcapfile = ""
    expected_output = None
    use_exceptions = True
    pcapdata = None

    def get_output(self, pcap):
        reader = PcapReader(pcap)
        reader.raise_exceptions = self.use_exceptions
        list(reader.process())

        key, exception = reader.exceptions.popitem()

        output = [
            exception["exception"],
            os.path.basename(os.path.normpath(exception["trace"][-1][0]))
        ]
        return output

    def test_pcap(self):
        if self.pcapdata is None:
            f = open(os.path.join("tests", "pcaps", self.pcapfile), "rb")
        else:
            f = io.BytesIO(self.pcapdata)

        assert self.expected_output == self.get_output(f)

class TestNoExceptionsUnknownEthernet(PcapTest):
    use_exceptions = False
    pcapfile = "unknownEthernet.pcap"
    expected_output = [
        UnknownEthernetProtocol,
        "reader.py"
    ]

class TestNoExceptionsUnknownIpProtocol(PcapTest):
    use_exceptions = False
    pcapfile = "unknownIpProtocol.pcap"
    expected_output = [
        UnknownIpProtocol,
        "reader.py"
    ]

class TestNoExceptionsUnknownDatalink(PcapTest):
    use_exceptions = False
    pcapdata = struct.pack(
        "IHHIIII", dpkt.pcap.TCPDUMP_MAGIC, dpkt.pcap.PCAP_VERSION_MAJOR,
        dpkt.pcap.PCAP_VERSION_MINOR, 0, 0, 1500, 0
    ) + b"A"*16

    expected_output = [
        UnknownDatalink,
        "reader.py"
    ]
