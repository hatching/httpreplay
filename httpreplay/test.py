# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import dpkt
import logging

import httpreplay.reader

from httpreplay.cut import dummy_handler, http_handler, forward_handler

log = logging.getLogger(__name__)

pcaps = [
    {
        "handlers": {
            80: http_handler(),
        },
        "pcapfile": "pcaps/test.pcap",
        "description": "Tests TCP reassembly and basic HTTP extraction",
        "format": lambda s, ts, sent, recv: (ts, sent.uri, len(recv.body)),
        "output": [
            (1278472581.261381, "/sd/facebook_icon.png", 3462),
            (1278472581.261490, "/sd/twitter_icon.png", 0),
            (1278472581.071695, "/sd/print.css?T_2_5_0_300", 0),
            (1278472581.580736, "/sd/logo2.png", 0),
            (1278472581.577512, "/sd/cs_i2_gradients.png?T_2_5_0_299", 0),
            (1278472581.584223, "/sd/cs_sic_controls_new.png?T_2_5_0_299", 0),
            (1278472581.071626, "/sd/idlecore-tidied.css?T_2_5_0_300", 0),
            (1278472580.653563, "/", 113331),
        ],
    },
    {
        "handlers": {
            25: dummy_handler(),
            80: http_handler(),
        },
        "pcapfile": "pcaps/2014-08-13-element1208_spm2.exe-sandbox-analysis.pcap",
        "description": "Extracts HTTP requests which have no response",
        "format": lambda s, ts, sent, recv: (sent.method, sent.uri, recv),
        "output": [
            ("POST", "/cmd.php", None),
            ("GET", "/cmd.php", None),
        ],
    },
    {
        "handlers": {
            25: forward_handler(),
            80: dummy_handler(),
        },
        "pcapfile": "pcaps/2014-08-13-element1208_spm2.exe-sandbox-analysis.pcap",
        "description": "Handle client disconnect and empty request",
        "format": lambda s, ts, sent, recv: (sent, recv),
        "output": [
            ("", "220 mx.google.com ESMTP v9si4604526wah.36\r\n"),
        ],
    },
    {
        "handlers": {
            80: http_handler(),
        },
        "pcapfile": "pcaps/2014-12-13-download.pcap",
        "description": "Extracts HTTP response cut off during transmission",
        "format": lambda s, ts, sent, recv: _pcap_2014_12_13(sent, recv),
        "output": [
            ("/zp/zp-core/zp-extensions/tiny_mce/plugins/ajaxfilemanager/inc/main.php", 451729, 35040),
        ],
    },
    {
        "handlers": {
            80: http_handler(),
            48754: dummy_handler(),
        },
        "pcapfile": "pcaps/2015-01-02-post-infection.pcap",
        "description": "Handles TCP Retransmission logic",
        "format": lambda s, ts, sent, recv: (s, sent.__class__.__name__),
        "output": [
            (("192.168.138.163", 48754, "219.70.113.58", 49199), "TCPRetransmission"),
            (("192.168.138.163", 48754, "74.78.180.226", 49202), "TCPRetransmission"),
            (("192.168.138.163", 48754, "68.80.249.239", 49204), "TCPRetransmission"),
            (("192.168.138.163", 48754, "190.244.193.78", 49205), "TCPRetransmission"),
            (("192.168.138.163", 48754, "173.28.84.203", 49207), "TCPRetransmission"),
            (("192.168.138.163", 48754, "73.199.51.213", 49208), "TCPRetransmission"),
            (("192.168.138.163", 48754, "66.81.47.199", 49209), "TCPRetransmission"),
            (("192.168.138.163", 48754, "186.9.145.31", 49211), "TCPRetransmission"),
            (("192.168.138.163", 48754, "68.193.144.105", 49213), "TCPRetransmission"),
            (("192.168.138.163", 48754, "99.235.167.54", 49214), "TCPRetransmission"),
            (("192.168.138.163", 48754, "126.119.135.45", 49215), "TCPRetransmission"),
            (("192.168.138.163", 48754, "219.70.113.58", 49218), "TCPRetransmission"),
            (("192.168.138.163", 48754, "24.253.145.21", 49220), "TCPRetransmission"),
        ],
    },
    {
        "handlers": {
            80: http_handler(),
        },
        "pcapfile": "pcaps/2015-10-08-Nuclear-EK-example-2-traffic.pcap",
        "description": "Handles TCP Spurious Retransmission logic",
        "format": lambda s, ts, sent, recv: getattr(sent, "uri", None),
        "output": [
            "/",
            "/wp-content/themes/mostashfa/hover/css/style_common.css",
            "/wp-content/themes/mostashfa/js/animatescroll.js",
            "/url?sa=l&rct=k&q=&esrc=y&source=web&cd=6&ved=aXFtVVktOQV0AQlBUSQ0JT1F&url=https%3A%2F%2F5584e38742.com&MhKWJ=399940b556&JMCQIUt=95578e0&ZhmZl=bVU1&1Q5U=eTG1ZX&5z9YSX0=dW1R&Fuj1T2=cFQ",
            "/viewtopic?0cFYRYP=2b1af084f&Fg5Ot=aUE1BT0daBERSVU8KDUkFA&A3uQ=cSVU8HGwM&ZysTUyT=0a0f23070&CnhL8C=dDHQACGwcDAE8DAQEFAAIKAgABT1VeBg..&HK2yA=bk9QUlNVUltVVBt",
            "/certainly?XcahV=eB&WOmmu=82d5a31898&TRH=cEBSQQFBwcBBA0G&5htVN5B=aU1xdVk9GXQRAUFVODQ1NAQEKSVdWVVdTXV&Wcy=bJQHVBUSQAfBQEcBgUfAQ&B3zj=dBgNOAklUfX&ZkxS=9e82ca&L6p=fjQ0kD",
            "/wp-content/plugins/ultimate-gallery/ultimate.swf",
            "/main.htm",
            "/file.htm",
            "/including?5EMZF=bU1FQW1RTG1ZXTwYcAwcfAAMcBwcCTwI&CH7Vl=57dfb5e&GffCcya=42b973&Vjrh8k=cGAQECAgsF&CPBXbg=aUV1uVV9TRl1NR1sDRFZXT1FV&PhfPwgY=dAAVNCws.",
            "/amount?5funIuS=bV1JaUlQfUFVOABsHAR0BBRsD&MvLsp=884f265e&Nxjv3F=aU1xdVk9GXQRAUFVODQ1NBwJOV1JX&ENLUF=dFBwADDQIE&L22=cAQBOBAE&KU3=21c1d81d&WST12=eA08FSU9gVnFhZkkA",
            "/viewtopic?8U9Z=0d31950a&DS7a2p=bXVJQHVBUSQAfBQEcB&2R7v=74b6fb&M5d4SvQ=aUV1uWUBOQV0AQlBUSVdWVVdT&KSsYgDJ=cgUfAQEBSQQFBwcBBA0GBgNODQ0.",
            "/harsh02.exe",
            "/harsh02.exe",
            "/favicon.ico",
            None,
        ],
    },
    {
        "handlers": {
            80: http_handler(),
            10771: dummy_handler(),
            29391: dummy_handler(),
        },
        "pcapfile": "pcaps/2015-10-13-Neutrino-EK-traffic-second-run.pcap",
        "description": "Handle IGMP packets and HTTP on port 80",
        "format": lambda s, ts, sent, recv: _pcap_2015_10_13(sent, recv),
        "output": [
            ("GET", "/"),
            ("GET", "/view.js"),
            ("POST", "/forum/db.php"),
            ("GET", "/domain/195.22.28.194"),
            "TCPRetransmission",
        ],
    },
    {
        "handlers": {
            80: dummy_handler(),
            "generic": http_handler(),
        },
        "pcapfile": "pcaps/2015-10-13-Neutrino-EK-traffic-second-run.pcap",
        "description": "Handle HTTP on non-default ports",
        "format": lambda s, ts, sent, recv: _pcap_2015_10_13(sent, recv),
        "output": [
            ("GET", "/bound/shout-32517633"),
            ("GET", "/august/Z250anJ5dGRq"),
            ("GET", "/snap/dHdmYmVpdXZs"),
            ("GET", "/full/a2hjY3hs"),
            "TCPRetransmission",
        ],
    },
]

def _pcap_2014_12_13(sent, recv):
    return sent.uri, int(recv.headers["content-length"]), len(recv.body)

def _pcap_2015_10_13(sent, recv):
    if isinstance(sent, dpkt.http.Request):
        return sent.method, sent.uri
    return sent.__class__.__name__

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
