# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import dpkt
import logging
import zlib

from httpreplay.exceptions import UnknownHttpEncoding
from httpreplay.shoddy import Protocol

log = logging.getLogger(__name__)

def _read_chunked(rfile):
    """
    Read a HTTP body with chunked transfer encoding.

    (adapted from mitmproxy's netlib.http.http1)
    """
    while True:
        line = rfile.readline(128)
        if line == b"":
            raise dpkt.NeedData("premature end of chunked body")
        if line != b"\r\n" and line != b"\n":
            try:
                length = int(line, 16)
            except ValueError:
                raise dpkt.UnpackError("Invalid chunked encoding length: {}".format(line))
            chunk = rfile.read(length)
            suffix = rfile.readline(5)
            if suffix != b"\r\n":
                raise dpkt.UnpackError("Malformed chunked body")
            if length == 0:
                return
            yield chunk

def parse_body(f, headers):
    """Return HTTP body parsed from a file object, given HTTP header dict.
    This is a modified version of dpkt.http.parse_body() which tolerates cut
    off HTTP bodies."""
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = "".join(_read_chunked(f))
    elif "content-length" in headers:
        n = int(headers["content-length"])
        body = f.read(n)
        # TODO Report a warning if we couldn't read the entire body (but don't
        # raise an exception as dpkt.http would do).
    elif "content-type" in headers:
        body = f.read()
    else:
        # XXX - need to handle HTTP/0.9
        body = ""

    return body

# We override the standard dpkt.http.parse_body() method with one that
# tolerates cut off HTTP bodies slightly better.
dpkt.http.parse_body = parse_body

def decode_gzip(ts, content):
    """Decompress HTTP gzip content, http://stackoverflow.com/a/2695575."""
    try:
        return zlib.decompress(content, 16 + zlib.MAX_WBITS)
    except zlib.error as e:
        if "incomplete or truncated stream" in e.message:
            log.warning(
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

def decode_identity(ts, content):
    """Identity encoding, an encoding that doesn't change the content."""
    return content

content_encodings = {
    "gzip": decode_gzip,
    "pack200-gzip": decode_pack200_gzip,
    "none": decode_none,
    "identity": decode_identity,
}

class _Response(object):
    """Dummy HTTP response object which only has the raw paremeter set."""
    def __init__(self, raw):
        self.raw = raw
        self.body = None

class HttpProtocol(Protocol):
    """Interprets the TCP or TLS stream as HTTP request and response."""

    def parse_request(self, ts, sent):
        try:
            res = dpkt.http.Request(sent)
            res.raw = sent
            return res
        except dpkt.UnpackError as e:
            if e.message.startswith("invalid http method"):
                log.warning("This is not a HTTP request (timestamp %f).", ts)
            else:
                log.warning(
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

            res.raw = recv
            return res
        except dpkt.NeedData as e:
            if e.message == "premature end of chunked body":
                log.warning("Chunked HTTP response is most likely missing "
                            "data in the network stream (timestamp %f).", ts)
            else:
                log.warning(
                    "Unknown HTTP response error (timestamp %f): %s", ts, e
                )
        except dpkt.UnpackError as e:
            if e.message == "missing chunk size":
                log.warning(
                    "Server informed us about a Chunked HTTP response but "
                    "there doesn't appear to be one (timestamp %f).", ts
                )

        # Return dummy object.
        return _Response(recv)

    def handle(self, s, ts, protocol, sent, recv):
        if protocol != "tcp" and protocol != "tls":
            self.parent.handle(s, ts, protocol, sent, recv)
            return

        req = res = None

        if sent:
            req = self.parse_request(ts, sent)

        protocols = {
            "tcp": "http",
            "tls": "https",
        }

        # Only try to decode the HTTP response if the request was valid HTTP.
        if req:
            res = self.parse_response(ts, recv)

            # Report this stream as being a valid HTTP stream.
            self.parent.handle(s, ts, protocols[protocol],
                               req or sent, res)
        else:
            # This wasn't a valid HTTP stream so we forward the original TCP
            # or TLS stream straight ahead to our parent.
            self.parent.handle(s, ts, protocol, sent, recv)

class SmtpProtocol(Protocol):
    """Interprets the SMTP protocol."""
