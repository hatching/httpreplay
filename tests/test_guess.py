# Copyright (C) 2021 Hatching B.V.
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

from httpreplay.reader import PcapReader
from httpreplay.transport import TCPPacketStreamer
from httpreplay.guess import tcp_guessprotocol

class TestDNS:

    handlers = {
        "generic": tcp_guessprotocol
    }

    def test_pcap(self):
        reader = PcapReader("tests/pcaps/test.pcap")
        reader.raise_exceptions = False
        reader.set_tcp_handler(TCPPacketStreamer(reader, self.handlers))

        http_uris = []
        for stream in reader.process():
            if stream[2] == "http":
                http_uris.append(stream[3].uri)

        assert http_uris == [
            '/sd/facebook_icon.png', '/sd/twitter_icon.png',
            '/sd/print.css?T_2_5_0_300', '/',
            '/sd/idlecore-tidied.css?T_2_5_0_300',
            '/sd/cs_sic_controls_new.png?T_2_5_0_299',
            '/sd/cs_i2_gradients.png?T_2_5_0_299', '/sd/logo2.png'
        ]
