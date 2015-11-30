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

class Packet(str):
    ts = None

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

    def handle(self, s, ts, sent, recv, special=None):
        srcip, srcport, dstip, dstport = s

        if special:
            if special not in self.handlers:
                log.warning("Unhandled special protocol %s", special)
            else:
                self.handlers[special].handle(s, ts, sent, recv)
            return

        if srcport in self.handlers:
            h = self.handlers[srcport].handle
            h((srcip, srcport, dstip, dstport), ts, recv, sent)
        elif dstport in self.handlers:
            h = self.handlers[dstport].handle
            h((dstip, dstport, srcip, srcport), ts, sent, recv)
        elif "generic" in self.handlers:
            h = self.handlers["generic"].handle
            h((dstip, dstport, srcip, srcport), ts, sent, recv)
        else:
            log.warning("Unhandled protocol port=%s/%s", srcport, dstport)

    def stream(self, ip, tcp, reverse=False):
        return (
            socket.inet_ntoa(ip.dst), tcp.dport,
            socket.inet_ntoa(ip.src), tcp.sport,
        ) if reverse else (
            socket.inet_ntoa(ip.src), tcp.sport,
            socket.inet_ntoa(ip.dst), tcp.dport,
        )

    def process(self, ts, ip, tcp):
        sn = self.stream(ip, tcp)
        sr = self.stream(ip, tcp, reverse=True)

        # This is a new connection.
        if sn not in self.streams and tcp.flags == dpkt.tcp.TH_SYN:
            self.streams[sn] = TCPStream(self, sn)

        if sn in self.streams:
            s = self.streams[sn]
            to_server = True
        elif sr in self.streams:
            s = self.streams[sr]
            to_server = False
        else:
            log.warning("Unknown stream %s:%s -> %s:%s!", *sn)
            return

        s.process(ts, tcp, to_server)

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
        self.origins = {}
        self.sent = ""
        self.recv = ""
        self.conn = False
        self.ts = None

        # Sequence numbers for the client and server, respectively.
        self.cli = None
        self.srv = None

        # The state of this TCP stream.
        self.state = "init_syn"

    def state_init_syn(self, ts, tcp, to_server):
        if tcp.flags != dpkt.tcp.TH_SYN:
            raise InvalidTcpPacketOrder(tcp)

        if tcp.data:
            raise UnexpectedTcpData(tcp)

        self.ts = ts
        self.cli = tcp.seq
        self.state = "init_syn_ack"

    def state_init_syn_ack(self, ts, tcp, to_server):
        # Retransmission of the SYN packet. Indicates that the server is not
        # responding within the given timeframe and thus might be a dead host.
        if to_server and tcp.flags == dpkt.tcp.TH_SYN:
            self.parent.handle(self.s, ts, TCPRetransmission(),
                               None, special="deadhost")
            return

        if to_server or tcp.flags != (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK):
            raise InvalidTcpPacketOrder(tcp)

        if tcp.data:
            raise UnexpectedTcpData(tcp)

        self.cli = tcp.ack
        self.srv = tcp.seq + 1
        self.state = "init_ack"

    def state_init_ack(self, ts, tcp, to_server):
        # Retransmission of the SYN ACK packet. Indicates that the server is
        # not responding within the given timeframe; nothing too special.
        if not to_server and tcp.flags == (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK):
            return

        if tcp.flags != dpkt.tcp.TH_ACK:
            raise InvalidTcpPacketOrder(tcp)

        if tcp.seq != self.cli:
            raise UnknownTcpSequenceNumber(tcp)

        if tcp.ack != self.srv:
            raise UnknownTcpSequenceNumber(tcp)

        if tcp.data:
            raise UnexpectedTcpData(tcp)

        self.state = "conn"

    def ack_packets(self, seq, ack, to_server):
        ret = Packet()
        while (seq, ack) in self.packets:
            buf = self.packets.pop((seq, ack))
            ret = Packet(buf + ret)
            ret.ts = buf.ts
            seq -= len(buf)
            self.origins.pop((seq, ack), None)

        if not self.ts:
            self.ts = ret.ts

        if to_server:
            self.sent += ret
        else:
            self.recv += ret

        return ret

    def state_conn(self, ts, tcp, to_server):
        if tcp.flags & dpkt.tcp.TH_ACK:
            self.ack_packets(tcp.ack, tcp.seq, not to_server)

        if tcp.flags & dpkt.tcp.TH_RST:
            self.state = "conn_closed"
            self.ack_packets(tcp.ack, tcp.seq - 1, not to_server)

        tcp_seq = tcp.seq + len(tcp.data)

        # If this is the final packet then the TCP sequence should be +1'd.
        if tcp.flags & dpkt.tcp.TH_FIN:
            self.state = "conn_finish"

            if to_server:
                self.cli = tcp_seq + 1
            else:
                self.srv = tcp_seq + 1

        if not tcp.data:
            return

        if tcp.data and to_server and self.recv:
            self.parent.handle(self.s, self.ts, self.sent, self.recv)
            self.sent = self.recv = ""
            self.ts = None

        packet = Packet(tcp.data)
        packet.ts = ts

        if (tcp.seq, tcp.ack) in self.origins:
            dup = self.packets.pop(self.origins.pop((tcp.seq, tcp.ack)))
            log.warning(
                "Found a retransmitted packet possibly with a different size "
                "than the original packet: %s vs %s (timestamps %s vs %s)!",
                len(dup), len(packet), dup.ts, packet.ts,
            )

        self.origins[tcp.seq, tcp.ack] = tcp_seq, tcp.ack
        self.packets[tcp_seq, tcp.ack] = packet

    def state_conn_closed(self, ts, tcp, to_server):
        # Enqueue this packet if any is provided.
        self.state_conn(ts, tcp, to_server)

        # And let packets loose straight away.
        self.ack_packets(tcp.seq + len(tcp.data), tcp.ack, to_server)

    def state_conn_finish(self, ts, tcp, to_server):
        # Still acknowledging older packets.
        if self.cli != tcp.ack and self.srv != tcp.ack:
            self.state_conn(ts, tcp, to_server)
            return

        if tcp.flags & dpkt.tcp.TH_ACK:
            if to_server:
                if self.srv != tcp.ack:
                    raise InvalidTcpPacketOrder(tcp)

                # Process any final packets.
                tcp.ack -= 1
                self.state_conn(ts, tcp, to_server)

                # Indicate the end of this connection.
                self.srv = None

            if not to_server:
                if self.cli != tcp.ack:
                    raise InvalidTcpPacketOrder(tcp)

                # Process any final packets.
                tcp.ack -= 1
                self.state_conn(ts, tcp, to_server)

                # Indicate the end of this connection.
                self.cli = None

        if tcp.flags & dpkt.tcp.TH_FIN:
            if to_server:
                self.cli = tcp.seq + 1
            else:
                self.srv = tcp.seq + 1

    states = {
        "init_syn": state_init_syn,
        "init_syn_ack": state_init_syn_ack,
        "init_ack": state_init_ack,
        "conn": state_conn,
        "conn_closed": state_conn_closed,
        "conn_finish": state_conn_finish,
    }

    def process(self, ts, tcp, to_server):
        self.states[self.state](self, ts, tcp, to_server)

    def finish(self):
        if self.sent or self.recv:
            self.parent.handle(self.s, self.ts, self.sent, self.recv)

        if self.packets:
            log.warning(
                "There are still packets in the pipeline. It is likely these "
                "were originally sent, then retransmitted with an extended "
                "length, acknowledged before the retransmission, and then "
                "sort of forgotten (timestamps %s).",
                " ".join("%s" % packet.ts for packet in self.packets.values())
            )

class TLSStream(Protocol):
    """Decrypts TLS streams into a TCPStream-like session."""

    tls_versions = {
        dpkt.ssl.SSL3_V: (3, 0),
        dpkt.ssl.TLS1_V: (3, 1),
        dpkt.ssl.TLS11_V: (3, 2),
        dpkt.ssl.TLS12_V: (3, 3),
    }
