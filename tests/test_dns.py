# Copyright (C) 2021 Hatching B.V.
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

from httpreplay import udpprotoparsers
from httpreplay.reader import PcapReader
from httpreplay.transport import UDPPacketStreamer
from httpreplay.protohandlers import DNS

class TestDNS:

    handlers = {
        53: DNS
    }

    def test_pcap(self):
        reader = PcapReader("tests/pcaps/test.pcap")
        reader.raise_exceptions = False
        reader.set_udp_handler(UDPPacketStreamer(reader, self.handlers))

        queries = []
        responses = []
        qnames = set()
        rdatas = set()
        for stream in reader.process():

            d = stream[3]
            if isinstance(d, udpprotoparsers.DNSQueries):
                queries.append(d)
                assert len(d.queries) > 0
                for q in d.queries:
                    qnames.add(f"{q.type} {q.name}")
            elif isinstance(d, udpprotoparsers.DNSResponses):
                responses.append(d)
                assert len(d.queries) > 0
                assert len(d.responses) > 0
                for r in d.responses:
                    rdatas.add(f"{r.type} {r.data}")

        assert len(queries) == 14
        assert len(responses) == 11

        assert qnames == {'A apache.slashdot.org', 'A bsd.slashdot.org',
                          'AAAA rss.slashdot.org',
                          'A amd.vendors.slashdot.org',
                          'A entertainment.slashdot.org',
                          'A features.slashdot.org', 'A e872.g.akamaiedge.net',
                          'AAAA entertainment.slashdot.org',
                          'A rss.slashdot.org', 'AAAA games.slashdot.org',
                          'A games.slashdot.org', 'AAAA e872.g.akamaiedge.net'}

        assert rdatas == {'A 216.34.181.48', 'A 216.34.181.47',
                          'CNAME ghs.l.google.com',
                          'CNAME sourceforge.feedproxy.ghs.google.com',
                          'A 74.125.47.121', 'A 96.17.211.172'}
