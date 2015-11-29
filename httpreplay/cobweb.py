# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import dpkt
import zlib

from httpreplay.exceptions import UnknownHttpEncoding
from httpreplay.shoddy import Protocol

def decode_gzip(content):
    """Decompress HTTP gzip content, http://stackoverflow.com/a/2695575."""
    return zlib.decompress(content, 16 + zlib.MAX_WBITS)

content_encodings = {
    "gzip": decode_gzip,
}

class HttpProtocol(Protocol):
    """Interprets the TCP or TLS stream as HTTP request and response."""

    def handle(self, s, ts, sent, recv):
        req = dpkt.http.Request(sent)
        res = dpkt.http.Response(recv)

        content_encoding = res.headers.get("content-encoding")
        if content_encoding:
            if content_encoding not in content_encodings:
                raise UnknownHttpEncoding(content_encoding)

            res.body = content_encodings[content_encoding](res.body)

        self.parent.handle(s, ts, req, res)
