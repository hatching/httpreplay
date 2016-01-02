# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import dpkt
import hashlib
import logging

import httpreplay.reader

from httpreplay.cut import dummy_handler, http_handler, forward_handler

log = logging.getLogger(__name__)

pcaps = [
    {
        "handlers": {
            80: http_handler,
        },
        "pcapfile": "pcaps/test.pcap",
        "description": "Tests TCP reassembly and basic HTTP extraction",
        "format": lambda s, ts, p, sent, recv: (ts, sent.uri, len(recv.body)),
        "output_count": 8,
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
            25: dummy_handler,
            80: http_handler,
        },
        "pcapfile": "pcaps/2014-08-13-element1208_spm2.exe-sandbox-analysis.pcap",
        "description": "Extracts HTTP requests which have no response",
        "format": lambda s, ts, p, sent, recv: (sent.method, sent.uri, recv),
        "output_count": 2,
        "output": [
            ("POST", "/cmd.php", ""),
            ("GET", "/cmd.php", ""),
        ],
    },
    {
        "handlers": {
            25: forward_handler,
            80: dummy_handler,
        },
        "pcapfile": "pcaps/2014-08-13-element1208_spm2.exe-sandbox-analysis.pcap",
        "description": "Handle client disconnect and empty request",
        "format": lambda s, ts, p, sent, recv: (s[0], sent, recv),
        "output_count": 2,
        "output": [
            ("172.16.165.133", "", "220 mx.google.com ESMTP v9si4604526wah.36\r\n"),
        ],
    },
    {
        "handlers": {
            80: http_handler,
        },
        "pcapfile": "pcaps/2014-12-13-download.pcap",
        "description": "Extracts HTTP response cut off during transmission",
        "format": lambda s, ts, p, sent, recv: _pcap_2014_12_13(sent, recv),
        "output_count": 1,
        "output": [
            ("/zp/zp-core/zp-extensions/tiny_mce/plugins/ajaxfilemanager/inc/main.php", 451729, 35040),
        ],
    },
    {
        "handlers": {
            80: http_handler,
            48754: dummy_handler,
        },
        "pcapfile": "pcaps/2015-01-02-post-infection.pcap",
        "description": "Handles TCP Retransmission logic",
        "format": lambda s, ts, p, sent, recv: (s, sent.__class__.__name__),
        "output_count": 24,
        "output": [
            (("192.168.138.163", 49199, "219.70.113.58", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49202, "74.78.180.226", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49204, "68.80.249.239", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49205, "190.244.193.78", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49207, "173.28.84.203", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49208, "73.199.51.213", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49209, "66.81.47.199", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49211, "186.9.145.31", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49213, "68.193.144.105", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49214, "99.235.167.54", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49215, "126.119.135.45", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49218, "219.70.113.58", 48754), "TCPRetransmission"),
            (("192.168.138.163", 49220, "24.253.145.21", 48754), "TCPRetransmission"),
        ],
    },
    {
        "handlers": {
            80: http_handler,
        },
        "pcapfile": "pcaps/2015-10-08-Nuclear-EK-example-2-traffic.pcap",
        "description": "Handles TCP Spurious Retransmission logic",
        "format": lambda s, ts, p, sent, recv: _pcap_2015_10_08(sent, recv),
        "output_count": 15,
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
        ],
    },
    {
        "handlers": {
            80: http_handler,
            10771: dummy_handler,
            29391: dummy_handler,
        },
        "pcapfile": "pcaps/2015-10-13-Neutrino-EK-traffic-second-run.pcap",
        "description": "Handle IGMP packets and HTTP on port 80",
        "format": lambda s, ts, p, sent, recv: _pcap_2015_10_13(sent, recv),
        "output_count": 11,
        "output": [
            ("GET", "/"),
            ("GET", "/view.js"),
            ("POST", "/forum/db.php"),
            ("GET", "/domain/195.22.28.194"),
        ],
    },
    {
        "handlers": {
            80: dummy_handler,
            "generic": http_handler,
        },
        "pcapfile": "pcaps/2015-10-13-Neutrino-EK-traffic-second-run.pcap",
        "description": "Handle HTTP on non-default ports",
        "format": lambda s, ts, p, sent, recv: _pcap_2015_10_13(sent, recv),
        "output_count": 4,
        "output": [
            ("GET", "/bound/shout-32517633"),
            ("GET", "/august/Z250anJ5dGRq"),
            ("GET", "/snap/dHdmYmVpdXZs"),
            ("GET", "/full/a2hjY3hs"),
        ],
    },
    {
        "handlers": {
            80: http_handler,
            443: dummy_handler,
        },
        "pcapfile": "pcaps/2015-10-12-Angler-EK-sends-Bedep-traffic.pcap",
        "description": "Extracts HTTP requests which are not acknowledged",
        "format": lambda s, ts, p, sent, recv: _pcap_2015_10_12(sent, recv),
        "output_count": 46,
        "output": """
            719acc7111036d05908a2bbc2edb59cb
            f9a8489b5110b8b06a8e97453257075d
            63afa4cf1601f01c4751039f8bbfdab4
            a7b807ebdb3843e2a3db757b5785792e
            c3bef09a66c24455685e794e9b08b459
            e59d25e237e5a3f3a6a06bd3faba7165
            27eeac51fc7eb06a22372c0bb3e85950
            0d621a81d3edbf9d58c76b01c37ed48b
            1520227cc1354cb144d30a50779ab95b
            a6298fa74bc8e61f94859dc90757c839
            28f06d78a5568dc4c2c9149682b67fa8
            cbb2bbdd3458221e9b51a20763f751c0
            d41d8cd98f00b204e9800998ecf8427e
            8a7f9fdc9b25a4b96b1da117f5b9d610
            eed8ec65a6dd9b05eed6d4a02e1439e4
            7008e1e1572f66b0fd30742e6ec4bb0f
            2eb071fbf1b8252932302e0946fad386
            2615820e5e0921ef0539f8651bf310a0
            e4407e614445327e4edb836494cc4ef0
            2098dedf3165609e56de26b8b0dc9661
            3efe4a011bae1c5315f20408a7a9491b
            9220f37dceb71a516e01c5a9d2e8366d
            d41d8cd98f00b204e9800998ecf8427e
            6593f3e7d45aca357b22be501d50ff01
            89205cebf4c75c8e70d896e3803c3fb8
            0f3427e4788f146600121d1e64b7b00d
            b920cf93d2b296f3ec0a6605be86ed36
            2c9e9b8a0e386e8db34827697160ec04
            e8a01c0c54b8b8e24f1b2810dc395ab3
            5f473a890d750f1147dc0c7cc4668481
            1d260bbdbdf8ae67145134958e5fd864
            1d67074ab1e6d3589da716a32fff6002
            3191b37145f3c1411ce1b5f9a1a07ab9
            cd9a2f577b63f7d9fd8d2bedcdd54bcd
            4971de24dd429af31e0359fbc5ca1460
            0067b30547ff79e4417356eb02e46032
            75f453a23ee7e801ca3ae66536f8fd5c
            a95fa6ffd78ab2a44ace57fa183b9d1f
            f3856d13d9d3d951d2e1856661345cf5
            65a65267a9d45cfd797bb4ade7534ca7
            72fd1899fdcd91e44c6c046775795d4d
            9bce0089598c20112cba73f37983da3e
            4260a4cd810990652fa22fad4f0e290f
            3bd5799f7aa98f8a752a383cdf53f461
            95ce680d2cb92ee3380432ad361d5273
        """.split() + [None],
    },
    {
        "handlers": {
            80: http_handler,
            443: dummy_handler,
        },
        # TODO Add per-stream support to this view.
        "pcapfile": "pcaps/EK_MALWARE_2014-09-29-Nuclear-EK-traffic_mailware-traffic-analysis.net.pcap",
        "description": "Extracts HTTP requests which are not acknowledged",
        "format": lambda s, ts, p, sent, recv: _pcap_2014_09_29(s, sent, recv),
        "output_count": 380,
        "output": [
            "56398e76be6355ad5999b262208a17c9",
            "07a37ca8f8898d5e1d8041ca37e8b399",
            "d41d8cd98f00b204e9800998ecf8427e",
            None,
        ],
    },
]

def _pcap_2014_12_13(sent, recv):
    return sent.uri, int(recv.headers["content-length"]), len(recv.body)

def _pcap_2015_10_13(sent, recv):
    if isinstance(sent, dpkt.http.Request):
        return sent.method, sent.uri
    return sent.__class__.__name__

def _pcap_2015_10_08(sent, recv):
    if isinstance(sent, dpkt.http.Request):
        return sent.uri
    return sent.__class__.__name__

def _pcap_2015_10_12(sent, recv):
    if isinstance(recv, dpkt.http.Response):
        return hashlib.md5(recv.body).hexdigest()

def _pcap_2014_09_29(s, sent, recv):
    # Only handle one particular stream.
    if s[1] != 49837 and s[3] != 49837:
        return

    if isinstance(recv, dpkt.http.Response):
        return hashlib.md5(recv.body).hexdigest()

def test_suite():
    errors = 0
    for pcap in pcaps:
        reader = httpreplay.reader.PcapReader(pcap["pcapfile"])
        reader.tcp = \
            httpreplay.smegma.TCPPacketStreamer(reader, pcap["handlers"])

        count = 0
        for s, ts, protocol, sent, recv in reader.process():
            output = pcap["format"](s, ts, sent, recv)
            if output not in pcap["output"]:
                log.critical("Error in unittest output for %s: %s",
                             pcap["pcapfile"], output)
                errors += 1
            count += 1

        if pcap.get("output_count") and count != pcap["output_count"]:
            log.critical(
                "Incorrect output count determined for %s: %s instead of %s",
                pcap["pcapfile"], count, pcap["output_count"]
            )

    log.info("Found %d errors.", errors)
    exit(1 if errors else 0)
