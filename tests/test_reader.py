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

here = os.path.abspath(os.path.dirname(__file__))

def test_unknownDatalinkException():
    r = PcapReader(io.BytesIO(
        struct.pack(
            "IHHIIII", dpkt.pcap.TCPDUMP_MAGIC, dpkt.pcap.PCAP_VERSION_MAJOR,
            dpkt.pcap.PCAP_VERSION_MINOR, 0, 0, 1500, 0
        ) + "A"*16
    ))
    with pytest.raises(UnknownDatalink):
        list(r.process())


def test_unknownEthernetProtocolException():
    r = PcapReader(open(os.path.join(here, "pcaps", "unknownEthernet.pcap"),
                        "rb"))
    with pytest.raises(UnknownEthernetProtocol):
        list(r.process())


def test_unknownIpProtocolException():
    r = PcapReader(open(os.path.join(here, "pcaps", "unknownIpProtocol.pcap"),
                        "rb"))
    with pytest.raises(UnknownIpProtocol):
        list(r.process())


class _TestPcap:
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
            with open(os.path.join(here, "pcaps", self.pcapfile), "rb") as f:
                assert self.expected_output == self.get_output(f)
        else:
            f = io.BytesIO(self.pcapdata)
            assert self.expected_output == self.get_output(f)


class TestNoExceptionsUnknownEthernet(_TestPcap):
    use_exceptions = False
    pcapfile = "unknownEthernet.pcap"
    expected_output = [
        UnknownEthernetProtocol,
        "reader.py"
    ]


class TestNoExceptionsUnknownIpProtocol(_TestPcap):
    use_exceptions = False
    pcapfile = "unknownIpProtocol.pcap"
    expected_output = [
        UnknownIpProtocol,
        "reader.py"
    ]


class TestNoExceptionsUnknownDatalink(_TestPcap):
    use_exceptions = False
    pcapdata = struct.pack(
            "IHHIIII", dpkt.pcap.TCPDUMP_MAGIC, dpkt.pcap.PCAP_VERSION_MAJOR,
            dpkt.pcap.PCAP_VERSION_MINOR, 0, 0, 1500, 0
        ) + "A"*16

    expected_output = [
        UnknownDatalink,
        "reader.py"
    ]
