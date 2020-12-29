# Copyright (C) 2015-2018 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import httpreplay.cobweb
from httpreplay.cobweb import bytes_to_str
import httpreplay.reader
import httpreplay.shoddy
import httpreplay.smegma

class ForwardProtocol(httpreplay.shoddy.Protocol):
    """Forwards the received packets up the ladder for raw interpretation."""

    def handle(self, s, ts, protocol, sent, recv, tlsinfo=None):
        self.parent.handle(s, ts, protocol, bytes_to_str(sent), bytes_to_str(recv), tlsinfo)

def dummy_handler():
    """Dummy Protocol handler that forwards packets to /dev/null."""
    return httpreplay.shoddy.Protocol()

def forward_handler():
    return ForwardProtocol()

def http_handler():
    return httpreplay.cobweb.HttpProtocol()

def https_handler(tlsmaster={}):
    return httpreplay.smegma.TLSStream(
        httpreplay.cobweb.HttpsProtocol(), tlsmaster
    )

def tls_handler(tlsmaster={}):
    return httpreplay.smegma.TLSStream(None, tlsmaster)

def smtp_handler():
    return httpreplay.cobweb.SmtpProtocol()
