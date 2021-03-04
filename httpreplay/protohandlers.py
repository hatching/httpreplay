# Copyright (C) 2015-2018 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import httpreplay.abstracts
import httpreplay.protoparsers
import httpreplay.udpprotoparsers
import httpreplay.reader
import httpreplay.transport

class ForwardProtocol(httpreplay.abstracts.Protocol):
    """Forwards the received packets up the ladder for raw interpretation."""

    def handle(self, s, ts, protocol, sent, recv, tlsinfo=None):
        self.parent.handle(
            s, ts, protocol, sent, recv, tlsinfo
        )

def dummy_handler():
    """Dummy Protocol handler that forwards packets to /dev/null."""
    return httpreplay.abstracts.Protocol()

def forward_handler():
    return ForwardProtocol()

def http_handler():
    return httpreplay.protoparsers.HttpProtocol()

def https_handler(tlsmaster={}):
    return httpreplay.transport.TLSStream(
        httpreplay.protoparsers.HttpsProtocol(), tlsmaster
    )

def tls_handler(tlsmaster={}):
    return httpreplay.transport.TLSStream(None, tlsmaster)

def smtp_handler():
    return httpreplay.protoparsers.SmtpProtocol()

def DNS():
    return httpreplay.udpprotoparsers.DNS()
