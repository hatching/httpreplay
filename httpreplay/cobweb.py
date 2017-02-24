# Copyright (C) 2015-2017 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import binascii
import logging
import re
import zlib

import dpkt
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
                raise dpkt.UnpackError(
                    "Invalid chunked encoding length: {}".format(line))
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
            if content_encoding and res.body:
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

    _commands = [
        "ehlo", "helo", "mail from", "rcpt to", "etrn",
        "turn", "atrn", "size", "etrn", "pipelining",
        "chunking", "data", "dsn", "rset", "vrfy",
        "help", "quit", "noop", "expn", "auth login",
        "auth plain", "auth cram-md5", "auth",
        "binarymime", "relay", "size", "starttls", "checkpoint",
        "enhancedstatuscodes", "8bitmime", "send"
    ]

    _command_field = {
        "ehlo": "hostname",
        "helo": "hostname",
        "mail from": "mail_from",
        "rcpt to": "mail_to"
    }

    # Min to max SMTP response codes
    _min = 100
    _max = 600

    def handle(self, s, ts, protocol, sent, recv):
        if protocol != "tcp":
            self.parent.handle(s, ts, protocol, sent, recv)
            return

        if self.stream is None:
            self.stream = self.parent.tcp.streams[s]

        self.parse_request(sent)
        self.parse_reply(recv)

        if self.stream.state in ["conn_finish", "conn_closed"]:
            self.parent.handle(s, ts, "smtp", self.request, self.reply)

    def init(self, *args, **kwargs):
        self.request = SmtpRequest()
        self.reply = SmtpReply()

        # Current smtp command from client
        self.command = None

        # Last smtp server response code
        self.last_rescode = 0

        # Last smtp server response message
        self.last_resmess = ""
        self.stream = None

    def _split(self, data, spliton="\r\n", always_list=False, maxsplit=-1):
        splitdata = filter(None, data.split(spliton, maxsplit))
        if len(splitdata) < 1:
            return None
        elif len(splitdata) == 1 and not always_list:
            return splitdata[0]
        else:
            return splitdata

    def _get_rescode(self, mes):
        """"
        Get the smtp server response code from a server reply
        Returns None if no valid code or no code exists in the message
        """
        if len(mes) < 3:
            return None

        code = 0
        try:
            code = int(mes[:3])
        except ValueError:
            return None
        if code >= self._min and code <= self._max:
            return code

    def get_command(self, request):
        """
        Get the smtp command from the request
        Returns a used command. Returns None if command not valid
        or no command exists in the message
        """
        command = None
        res = request.lower()
        for c in self._commands:
            if res.startswith(c):
                command = c
                break

        return command

    def parse_request(self, request):
        """"
        Parses the requests sent by an smtp client. Values are stored in
        a SmtpRequest object
        """
        self.request.raw.append(request)
        self.command = self.get_command(request)

        if self.command is not None:
            r = re.compile(re.escape(self.command), re.IGNORECASE)
            self.data = r.sub("", request)
        else:
            self.data = request

        if self.command in self._command_field:
            field = self._command_field[self.command]

            if self.command in ["mail from", "rcpt to"]:
                setattr(self.request, field,
                        re.findall('<(.*?)>', self.data, re.DOTALL))
            else:
                setattr(self.request, field, self._split(self.data))

        elif self.command is not None and self.command.startswith("auth"):
            self.request.auth_type = self.command
            self._handle_auth()
        elif self.last_rescode == 334:
            self._handle_auth()
        elif self.last_rescode == 354:
            headers_mes = self._split(request, spliton="\r\n\r",
                                      always_list=True, maxsplit=1)
            self.request.headers = self._split(headers_mes[0])
            self.request.message = headers_mes[1]

    def _handle_auth(self):
        """
        Determines what kind of authentication type was used
        and tries to collect the credentials based on the used authentication
        type

        http://www.samlogic.net/articles/smtp-commands-reference-auth.htm
        """
        if len(self.data) > 0:
            if self.command == "auth plain":
                self._handle_auth_plain_data(self.data)
            elif self.command == "auth login":
                try:
                    self.request.username = self.data.decode("base64")
                except binascii.Error as e:
                    return
            elif "UGFzc3dvcmQ6" in self.last_resmess:
                try:
                    self.request.password = self.data.decode("base64")
                except binascii.Error:
                    return
            elif "VXNlcm5hbWU6" in self.last_resmess:
                try:
                    self.request.username = self.data.decode("base64")
                except binascii.Error:
                    return
            elif self.last_rescode == 334 and self.request.auth_type == "auth plain":
                self._handle_auth_plain_data(self.data)
            elif self.last_rescode == 334 and self.request.auth_type == "auth cram-md5":
                try:
                    self.request.username = self._split(
                        self.data.decode("base64"), spliton=" ", maxsplit=1
                    )[0]
                except (binascii.Error, IndexError):
                    return

    def _handle_auth_plain_data(self, data):
        try:
            user_pass = self._split(data.decode("base64"), spliton="\x00")
            self.request.username = user_pass[0]
            self.request.password = user_pass[1]
        except (binascii.Error, IndexError):
            return

    def parse_reply(self, reply):
        """
        Parses the response sent by an smtp server. Values are stored in
        a SmtpReply object
        """
        self.reply.raw.append(reply)
        self.last_resmess = reply

        code = self._get_rescode(reply)
        self.last_rescode = code

        if code is None:
            return

        if code == 250:
            self.reply.ok_responses.extend(self._split(reply, always_list=True))
        elif code == 220:
            self.reply.ready_message = self._split(reply)


class SmtpRequest(object):

    def __init__(self):
        self.hostname = None
        self.password = None
        self.username = None
        self.auth_type = None
        self.mail_from = None
        self.message = None
        self.mail_to = None
        self.headers = None
        self.raw = []


class SmtpReply(object):

    def __init__(self):
        self.ready_message = None
        self.ok_responses = []
        self.raw = []
