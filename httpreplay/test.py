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
        "format": lambda s, ts, sent, recv: (s, sent.__class__.__name__),
        "output": [
            (('192.168.138.163', 48754, '219.70.113.58', 49199), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '74.78.180.226', 49202), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '68.80.249.239', 49204), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '190.244.193.78', 49205), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '173.28.84.203', 49207), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '73.199.51.213', 49208), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '66.81.47.199', 49209), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '186.9.145.31', 49211), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '68.193.144.105', 49213), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '99.235.167.54', 49214), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '126.119.135.45', 49215), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '219.70.113.58', 49218), 'TCPDeadHost'),
            (('192.168.138.163', 48754, '24.253.145.21', 49220), 'TCPDeadHost'),
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
