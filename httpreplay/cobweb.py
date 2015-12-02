# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import dpkt
import logging
import zlib

from httpreplay.exceptions import UnknownHttpEncoding
from httpreplay.shoddy import Protocol

log = logging.getLogger(__name__)

class _strip_content_length(dict):
    """Keeps the Content-Length header but returns False when dpkt.http checks
    whether we have the key in our dictionary."""

    def __contains__(self, key):
        if key == "content-length":
            return False

        return super(_strip_content_length, self).__contains__(key)

def strip_content_length(f):
    return _strip_content_length(_parse_headers(f))

# We pretend as if the "Content-Length" header is not available.
_parse_headers = dpkt.http.parse_headers
dpkt.http.parse_headers = strip_content_length

def decode_gzip(ts, content):
    """Decompress HTTP gzip content, http://stackoverflow.com/a/2695575."""
    try:
        return zlib.decompress(content, 16 + zlib.MAX_WBITS)
    except zlib.error as e:
        if "incomplete or truncated stream" in e.message:
            log.critical(
                "Error unpacking GZIP stream in HTTP response, it is quite "
                "likely that something went wrong during the process of "
                "stitching TCP/IP packets back together (timestamp %f).", ts
            )

def decode_pack200_gzip(ts, content):
    """Decompress HTTP pack200/gzip content, a gzip-compressed compressed
    JAR file.."""
    log.critical(
        "Proper pack200-gzip support is required to unpack this HTTP "
        "response but this has not been implemented yet (timestamp %f).", ts
    )

def decode_none(ts, content):
    """None encoding."""
    return content

content_encodings = {
    "gzip": decode_gzip,
    "pack200-gzip": decode_pack200_gzip,
    "none": decode_none,
}

class HttpProtocol(Protocol):
    """Interprets the TCP or TLS stream as HTTP request and response."""

    def parse_request(self, ts, sent):
        try:
            return dpkt.http.Request(sent)
        except dpkt.UnpackError as e:
            if e.message.startswith("invalid http method"):
                log.warning("This is not a HTTP request (timestamp %f).", ts)
            else:
                log.critical(
                    "Unknown HTTP request error (timestamp %f): %s", ts, e
                )

    def parse_response(self, ts, recv):
        try:
            res = dpkt.http.Response(recv)

            # Decode the content encoding.
            content_encoding = res.headers.get("content-encoding")
            if content_encoding:
                if content_encoding not in content_encodings:
                    raise UnknownHttpEncoding(content_encoding)

                res.body = content_encodings[content_encoding](ts, res.body)

            return res
        except dpkt.NeedData as e:
            if e.message == "premature end of chunked body":
                log.warning("Chunked HTTP response is most likely missing "
                            "data in the network stream (timestamp %f).", ts)
            else:
                log.critical(
                    "Unknown HTTP response error (timestamp %f): %s", ts, e
                )
        except dpkt.UnpackError as e:
            if e.message == "missing chunk size":
                log.warning(
                    "Server informed us about a Chunked HTTP response but "
                    "there doesn't appear to be one (timestamp %f).", ts
                )

    def handle(self, s, ts, sent, recv, special=None):
        if special:
            self.parent.handle(s, ts, sent, recv, special)
            return

        req = res = None

        if sent:
            req = self.parse_request(ts, sent)

        # Only try to decode the HTTP response if the request was valid HTTP.
        if req and recv:
            res = self.parse_response(ts, recv)

        self.parent.handle(s, ts, req or sent, res or recv)

class SmtpProtocol(Protocol):
    """Interprets the SMTP protocol."""
