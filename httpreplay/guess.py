# Copyright (C) 2021 Hatching B.V.
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

from httpreplay.abstracts import Protocol
from httpreplay.protohandlers import http_handler

http_keywords = (
    b"GET /", b"POST /", b"HEAD /", b"PUT /", b"DELETE /", b"CONNECT /",
    b"OPTIONS /", b"PATCH /", b"HTTP/0.9 ", b"HTTP/1.0 ", b"HTTP/1.1 "
)

class TCPGuessProtocol(Protocol):

    def init(self):
        self.guessed_proto = None
        self.guessed = False

    def handle(self, s, ts, protocol, sent, recv, tlsinfo=None):
        # The protocol was guessed in a previous part of this stream.
        # Forward this data to the guessed protocol.
        if self.guessed_proto:
            return self.guessed_proto.handle(
                s, ts, protocol, sent, recv, tlsinfo
            )
        # No protocol was guessed in a previous stream. Forward data back to
        # parent.
        elif self.guessed:
            return self.parent.handle(s, ts, protocol, sent, recv, tlsinfo)

        self.guessed = True
        proto_handler = None
        if sent and sent.startswith(http_keywords) \
                or recv and recv.startswith(http_keywords):
            proto_handler = http_handler

        # A protocol was guessed, initialize it and use it for the rest of
        # the TCP stream.
        if proto_handler:
            self.guessed_proto = proto_handler()
            self.guessed_proto.parent = self.parent
            return self.guessed_proto.handle(
                s, ts, protocol, sent, recv, tlsinfo
            )

        # No protocol was guessed, forward stream data back to parent.
        return self.parent.handle(s, ts, protocol, sent, recv, tlsinfo)

def tcp_guessprotocol():
    return TCPGuessProtocol()
