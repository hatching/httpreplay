# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import httpreplay.cobweb
import httpreplay.reader
import httpreplay.shoddy
import httpreplay.smegma

class ForwardProtocol(httpreplay.shoddy.Protocol):
    """Forwards the received packets up the ladder for raw interpretation."""

    def handle(self, s, ts, protocol, sent, recv):
        self.parent.handle(s, ts, protocol, sent, recv)

def dummy_handler():
    """Dummy Protocol handler that forwards packets to /dev/null."""
    return httpreplay.shoddy.Protocol()

def forward_handler():
    return ForwardProtocol()

def http_handler():
    return httpreplay.cobweb.HttpProtocol()

def https_handler(tlsmaster={}):
    return httpreplay.smegma.TLSStream(
        httpreplay.cobweb.HttpProtocol(), tlsmaster
    )

def tls_handler(tlsmaster={}):
    return httpreplay.smegma.TLSStream(None, tlsmaster)

def smtp_handler():
    return httpreplay.cobweb.SmtpProtocol()
