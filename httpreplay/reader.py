# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import dpkt

from httpreplay.exceptions import (
    UnknownDatalink, UnknownEthernetProtocol, UnknownIpProtocol,
)

class PcapReader(object):
    """Iterates over a PCAP file and yields all interesting events after
    having each packet processed by the various callback functions that can be
    provided by the user."""

    def __init__(self, filepath):
        self.pcap = dpkt.pcap.Reader(open(filepath, "rb"))
        self.tcp = None
        self.udp = None
        self.values = []

    def set_tcp_handler(self, tcp):
        self.tcp = tcp

    def set_udp_handler(self, udp):
        self.udp = udp

    def process(self):
        for ts, packet in self.pcap:
            if isinstance(packet, str):
                if self.pcap.datalink() == dpkt.pcap.DLT_EN10MB:
                    packet = dpkt.ethernet.Ethernet(packet)
                elif self.pcap.datalink() == 101:
                    packet = dpkt.ip.IP(packet)
                else:
                    raise UnknownDatalink(packet)

            if isinstance(packet, dpkt.ethernet.Ethernet):
                if isinstance(packet.data, dpkt.ip.IP):
                    packet = packet.data
                elif isinstance(packet.data, dpkt.arp.ARP):
                    packet = packet.data
                else:
                    raise UnknownEthernetProtocol(packet)

            if isinstance(packet, dpkt.ip.IP):
                ip = packet
                if packet.p == dpkt.ip.IP_PROTO_ICMP:
                    packet = packet.data
                elif packet.p == dpkt.ip.IP_PROTO_TCP:
                    packet = packet.data
                elif packet.p == dpkt.ip.IP_PROTO_UDP:
                    packet = packet.data
                else:
                    raise UnknownIpProtocol(packet)
            else:
                ip = None

            if isinstance(packet, dpkt.tcp.TCP):
                self.tcp and self.tcp.process(ts, ip, packet)

            if isinstance(packet, dpkt.udp.UDP):
                self.udp and self.udp.process(ts, ip, packet)

            while self.values:
                yield self.values.pop(0)

        self.tcp and self.tcp.finish()
        while self.values:
            yield self.values.pop(0)

        self.udp and self.udp.finish()
        while self.values:
            yield self.values.pop(0)

    def handle(self, s, ts, sent, recv):
        self.values.append((s, ts, sent, recv))
