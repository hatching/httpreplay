# Copyright (C) 2021 Hatching B.V.
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

from httpreplay.abstracts import Protocol
from httpreplay.protohandlers import http_handler, tls_handler, smtp_handler

http1_keywords = (
    b"GET /", b"POST /", b"HEAD /", b"PUT /", b"DELETE /", b"CONNECT /",
    b"OPTIONS /", b"PATCH /", b"TRACE /", b"HTTP/0.9 ", b"HTTP/1.0 ",
    b"HTTP/1.1 "
)


def _guess_http(sent, recv, tlskeys, parent, previous_guess):
    if sent and sent.startswith(http1_keywords):
        handler = http_handler()
        handler.parent = parent
        return handler

def _guess_tls(sent, recv, tlskeys, parent, previous_guess):
    # Do not guess again if the previous guess already was TLS. This
    # can cause infinite recursive loops.
    if previous_guess == "tls":
        return

    # Min length of 5 bytes. uint8 content type, uint16 version, uint16 length
    if sent and len(sent) >= 5:
        # Message content type 20-23
        if 20 <= sent[0] <= 23:
            # SSL and TLS version byte checks
            if sent[1:3] in (b"\x02\x00", b"\x03\x00", b"\x03\x01",
                           b"\x03\x02", b"\x03\x03", b"\x03\x04"):

                tlshandler = tls_handler(tlskeys)
                # Set new guesser as a parent of the tls handler so the
                # decrypted data's protocol can be guessed.
                guesser = TCPGuessProtocol(tlskeys, previous_guess="tls")
                guesser.parent = parent
                tlshandler.parent = guesser
                return tlshandler

def _guess_smtp(sent, recv, tlskeys, parent, previous_guess):
    if recv and len(recv) > 1:
        if recv.startswith(b"220 ") and b" ESMTP" in recv or b" SMTP" in recv:
            smtp = smtp_handler()
            smtp.parent = parent
            return smtp

    if sent and len(sent) >= 5:
        if sent[:5].lower() in (b"ehlo ", b"helo "):
            smtp = smtp_handler()
            smtp.parent = parent
            return smtp

class TCPGuessProtocol(Protocol):

    # A guesser must return an initalized protocol handler with the guessers
    # parent set in its parent chain.
    _protocol_guessers = (_guess_http, _guess_tls, _guess_smtp)

    def init(self, secrets={}, previous_guess=None):
        self.previous_guess = previous_guess
        self.guessed_proto = None
        self.guessed = False
        self.secrets = secrets

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
        for guesser in self._protocol_guessers:
            proto_handler = guesser(
                sent, recv, self.secrets, self.parent, self.previous_guess
            )
            if proto_handler:
                # A protocol was guessed, use it for the rest of the TCP
                # stream.
                self.guessed_proto = proto_handler
                return self.guessed_proto.handle(
                    s, ts, protocol, sent, recv, tlsinfo
                )

        # No protocol was guessed, forward stream data back to parent.
        return self.parent.handle(s, ts, protocol, sent, recv, tlsinfo)

def tcp_guessprotocol(secrets={}):
    return TCPGuessProtocol(secrets=secrets)
