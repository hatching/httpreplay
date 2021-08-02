# Copyright (C) 2021 Hatching B.V.
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

from httpreplay.reader import PcapReader
from httpreplay.transport import TCPPacketStreamer
from httpreplay.guess import tcp_guessprotocol
from httpreplay.misc import read_tlsmaster

class GuessTest:

    pcap = None
    handlers = {
        "generic": tcp_guessprotocol
    }

    def format(self, s, ts, p, sent, recv):
        raise NotImplementedError

    def _make_output(self):
        reader = PcapReader(self.pcap)
        reader.raise_exceptions = False
        reader.set_tcp_handler(TCPPacketStreamer(reader, self.handlers))

        return [self.format(*stream) for stream in reader.process()]


class TestGuessHTTP(GuessTest):

    pcap = "tests/pcaps/test.pcap"

    def format(self, s, ts, p, sent, recv):
        if p == "http":
            return sent.uri

    def test_pcap(self):
        expect = [
            '/sd/facebook_icon.png', '/sd/twitter_icon.png',
            '/sd/print.css?T_2_5_0_300', '/',
            '/sd/idlecore-tidied.css?T_2_5_0_300',
            '/sd/cs_sic_controls_new.png?T_2_5_0_299',
            '/sd/cs_i2_gradients.png?T_2_5_0_299', '/sd/logo2.png'
        ]

        assert expect == self._make_output()

class TestGuessTLSHTTP(GuessTest):
    pcap = "tests/pcaps/2019-05-01-airfrance-fr-traffic.pcap"

    handlers = {
        "generic": lambda: tcp_guessprotocol(
            read_tlsmaster(
                "tests/tlsmasters/2019-05-01-airfrance-fr-tlsmaster.mitm"
            )
        )
    }

    https_uris = [
        "https /FR/common/common/img/hopCard/common/top_right_border.png",
        "https /FR/fr/local/json/tbaf/destinations/iatas.json",
        "https /log",
    ]

    http_uris = [
        "http /edgedl/release2/update2/ANrcqf-u-0tl_1.3.34.7/GoogleUpdateSetup.exe?cms_redirect=yes&mip=5.48.205.29&mm=28&mn=sn-cv0tb0xn-uanl&ms=nvh&mt=1555914529&mv=u&pl=18&shardbypass=yes",
        "http /ncsi.txt",
    ]

    def format(self, s, ts, p, sent, recv):
        return f"{p} {sent.uri}"

    def test_tls_http(self):
        output = self._make_output()
        for proto_uri in self.https_uris:
            assert proto_uri in output

    def test_http(self):
        output = self._make_output()
        for proto_uri in self.http_uris:
            assert proto_uri in output
