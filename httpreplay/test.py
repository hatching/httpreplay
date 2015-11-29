# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import logging

import httpreplay.reader

from httpreplay.cut import http_handler

log = logging.getLogger(__name__)

pcaps = [
    {
        "handlers": {
            80: http_handler(),
        },
        "pcapfile": "pcaps/test.pcap",
        "format": lambda s, ts, sent, recv: (ts, sent.uri, len(recv.body)),
        "output": [
            (1278472581.577512, '/sd/facebook_icon.png', 3462),
            (1278472581.580736, '/sd/twitter_icon.png', 0),
            (1278472581.584223, '/sd/print.css?T_2_5_0_300', 0),
            (1278472581.580736, '/sd/logo2.png', 0),
            (1278472581.577512, '/sd/cs_i2_gradients.png?T_2_5_0_299', 0),
            (1278472581.584223, '/sd/cs_sic_controls_new.png?T_2_5_0_299', 0),
            (1278472581.071626, '/sd/idlecore-tidied.css?T_2_5_0_300', 0),
            (1278472580.653563, '/', 113331),
        ],
    },
    {
        "handlers": {
            80: http_handler(),
        },
        "pcapfile": "pcaps/2014-08-13-element1208_spm2.exe-sandbox-analysis.pcap",
        "format": lambda s, ts, sent, recv: (sent.method, sent.uri, recv),
        "output": [
            ("POST", "/cmd.php", None),
            ("GET", "/cmd.php", None),
        ],
    },
    {
        "handlers": {
            80: http_handler(),
        },
        "pcapfile": "pcaps/2014-12-13-download.pcap",
        "format": lambda s, ts, sent, recv: _pcap_2014_12_13(sent, recv),
        "output": [
            ("/zp/zp-core/zp-extensions/tiny_mce/plugins/ajaxfilemanager/inc/main.php", 451729, 35040),
        ],
    },
    {
        "handlers": {
            80: http_handler(),
        },
        "pcapfile": "pcaps/2015-01-02-post-infection.pcap",
        "format": lambda s, ts, sent, recv: (sent.__class__.__name__, recv),
        "output": [
            ("TCPDeadHost", None),
        ],
    },
]

def _pcap_2014_12_13(sent, recv):
    return sent.uri, int(recv.headers["content-length"]), len(recv.body)

def test_suite():
    errors = 0
    for pcap in pcaps:
        reader = httpreplay.reader.PcapReader(pcap["pcapfile"])
        reader.tcp = \
            httpreplay.smegma.TCPPacketStreamer(reader, pcap["handlers"])

        for s, ts, sent, recv in reader.process():
            output = pcap["format"](s, ts, sent, recv)
            if output not in pcap["output"]:
                log.critical("Error in unittest output for %s: %s",
                             pcap["pcapfile"], output)
                errors += 1

    log.info("Found %d errors.", errors)
    exit(1 if errors else 0)
