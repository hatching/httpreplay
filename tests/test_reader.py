# Copyright (C) 2017 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import dpkt.pcap
import io
import pytest
import struct

from httpreplay.exceptions import UnknownDatalink
from httpreplay.reader import PcapReader

def test_reader():
    r = PcapReader(io.BytesIO(
        struct.pack(
            "IHHIIII", dpkt.pcap.TCPDUMP_MAGIC, dpkt.pcap.PCAP_VERSION_MAJOR,
            dpkt.pcap.PCAP_VERSION_MINOR, 0, 0, 1500, 0
        ) + "A"*16
    ))
    with pytest.raises(UnknownDatalink):
        list(r.process())
