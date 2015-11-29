# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import dpkt
import logging
import socket

from httpreplay.shoddy import Protocol

from httpreplay.exceptions import (
    UnknownTcpSequenceNumber, UnexpectedTcpData, InvalidTcpPacketOrder,
)

log = logging.getLogger(__name__)

def tcp_flags(tcp):
    return "".join([
        "s" if tcp.flags & dpkt.tcp.TH_SYN else "",
        "a" if tcp.flags & dpkt.tcp.TH_ACK else "",
        "r" if tcp.flags & dpkt.tcp.TH_RST else "",
        "f" if tcp.flags & dpkt.tcp.TH_FIN else "",
    ])

class TCPPacketStreamer(Protocol):
    """Translates TCP/IP packet streams into rich streams of stitched
    together packets that can be processed further by specific protocol
    handlers on top of the TCP/IP protocol (e.g., HTTP, SMTP, etc)."""

    def init(self, handlers):
        self.streams = {}
        self.handlers = handlers
        self.spurious = {}

        # For each handler we follow it all the way to the end (so to support
        # nested protocol interpreters such as, e.g., HTTPS) and put our
        # parent, which happens to be the pcap reader generally speaking, as
        # protocol parent.
        for handler in self.handlers.values():
            while handler.parent:
                handler = handler.parent

            handler.parent = self.parent

    def handle(self, s, ts, sent, recv):
        srcip, srcport, dstip, dstport = s

        if srcport in self.handlers:
            h = self.handlers[srcport].handle
            h((srcip, srcport, dstip, dstport), ts, sent, recv)
        elif dstport in self.handlers:
            h = self.handlers[dstport].handle
            h((dstip, dstport, srcip, srcport), ts, recv, sent)
        elif "generic" in self.handlers:
            h = self.handlers["generic"].handle
            h((dstip, dstport, srcip, srcport), ts, sent, recv)
        else:
            log.warning("Unhandled protocol port=%s/%s", srcport, dstport)

    def stream(self, ip, tcp, reverse=False):
        return (
            socket.inet_ntoa(ip.dst), tcp.sport,
            socket.inet_ntoa(ip.src), tcp.dport,
        ) if reverse else (
            socket.inet_ntoa(ip.src), tcp.dport,
            socket.inet_ntoa(ip.dst), tcp.sport,
        )

    def process(self, ts, ip, tcp):
        sn = self.stream(ip, tcp)
        sr = self.stream(ip, tcp, reverse=True)

        # This is a new connection.
        if sn not in self.streams and tcp_flags(tcp) == "s":
            s = self.streams[sn] = TCPStream(self, sn)
            s.ts = ts
            s.cli = tcp.seq
            if tcp.data:
                raise UnexpectedTcpData(tcp)
            return

        # Server reply to the new connection.
        if sr in self.streams and tcp_flags(tcp) == "sa":
            s = self.streams[sr]
            if tcp.ack != s.cli + 1:
                # Handle "TCP Spurious Retransmission" packets which in this
                # case most-likely represent duplicate packets.
                # https://blog.packet-foo.com/2013/06/spurious-retransmissions/
                if (tcp.ack, tcp.seq) in self.spurious:
                    return

                raise UnknownTcpSequenceNumber(tcp)
            if tcp.data:
                raise UnexpectedTcpData(tcp)

            self.spurious[tcp.ack, tcp.seq] = None
            s.cli = tcp.ack
            s.srv = tcp.seq + 1
            return

        # Client reply to the new connection.
        if sn in self.streams and not self.streams[sn].conn:
            s = self.streams[sn]

            # Retransmission of a TCP/IP connection. Or in other words, this
            # could be a dead host.
            if tcp_flags(tcp) == "s" and not s.srv:
                self.parent.handle(sn, ts, TCPRetransmission(), None)
                return

            if tcp_flags(tcp) != "a":
                raise InvalidTcpPacketOrder(tcp)
            if tcp.seq != s.cli:
                raise UnknownTcpSequenceNumber(tcp)
            if tcp.ack != s.srv:
                raise UnknownTcpSequenceNumber(tcp)
            if tcp.data:
                raise UnexpectedTcpData(tcp)

            s.conn = True
            return

        # Packet from the client to the server.
        if sn in self.streams and tcp.data:
            self.streams[sn].process(sn, ts, tcp, True)

        # Packet from the server to the client.
        if sr in self.streams and tcp.data:
            self.streams[sr].process(sr, ts, tcp, False)

    def finish(self):
        for stream in self.streams.values():
            stream.finish()

class TCPRetransmission(Protocol):
    """Indicates a dead host, one that we were not able to connect to during
    the time that this PCAP was alive and kicking."""

class TCPStream(Protocol):
    """Concatenates rich TCP/IP streams into question/response sequences."""

    def init(self, s):
        self.s = s
        self.packets = {}
        self.sent = ""
        self.recv = ""
        self.conn = False
        self.ts = None

        # Sequence numbers for the client and server, respectively.
        self.cli = None
        self.srv = None

    def process(self, s, ts, tcp, to_server):
        self.packets[tcp.seq, tcp.ack] = tcp.data

        # TCP streams may have many question/response sequences.
        if to_server and self.recv:
            self.parent.handle(self.s, ts, self.sent, self.recv)
            self.ts, self.sent, self.recv = ts, "", ""

        while (self.cli, self.srv) in self.packets:
            packet = self.packets.pop((self.cli, self.srv))
            self.sent += packet
            self.cli += len(packet)

        while (self.srv, self.cli) in self.packets:
            packet = self.packets.pop((self.srv, self.cli))
            self.recv += packet
            self.srv += len(packet)

    def finish(self):
        if self.sent or self.recv:
            self.parent.handle(self.s, self.ts, self.sent, self.recv)

class TLSStream(Protocol):
    """Decrypts TLS streams into a TCPStream-like session."""

    tls_versions = {
        dpkt.ssl.SSL3_V: (3, 0),
        dpkt.ssl.TLS1_V: (3, 1),
        dpkt.ssl.TLS11_V: (3, 2),
        dpkt.ssl.TLS12_V: (3, 3),
    }
