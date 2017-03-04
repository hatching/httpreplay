# Copyright (C) 2015-2017 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import binascii
import dpkt
import logging
import re
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
                raise dpkt.UnpackError(
                    "Invalid chunked encoding length: %s" % line
                )
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

    _unimplemented = [
        "etrn", "turn", "atrn", "size" ,
        "etrn", "pipelining", "chunking", "data",
        "dsn", "rset", "vrfy", "help" ,
        "quit", "noop", "expn", "binarymime",
        "relay", "size", "starttls", "checkpoint",
        "enhancedstatuscodes", "8bitmime", "send"
    ]

    def init(self, *args, **kwargs):
        self.request = SmtpRequest()
        self.reply = SmtpReply()

        # Current smtp command from client
        self.command = None

        # Last smtp server response code
        self.rescode = 0

        # Last smtp server response message
        self.message = ""

        # Used in handler() to determine if the TCP stream
        # was closed or is finished
        self.stream = None

        # Contains the functions to be called when this command is the first
        # string in a request message
        self._commands = {
            "ehlo": self.handle_hostname,
            "helo": self.handle_hostname,
            "mail": self.handle_mail,
            "rcpt": self.handle_rcpt,
            "auth": self.handle_auth
        }

        # Contains the functions to be called
        # in the request handler after the server sents this response code
        self._res_codes = {
            334: self.handle_auth_serv_response,
            354: self.handle_mailbody,
        }

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

    def handle_hostname(self, data):
        if len(data) > 1:
            self.request.hostname = data[1]

    def handle_rcpt(self, data):
        for val in data:
            self.request.mail_to.extend(re.findall("<(.*?)>", val, re.DOTALL))

    def handle_mail(self, data):
        for val in data:
            self.request.mail_from.extend(re.findall("<(.*?)>", val, re.DOTALL))

    def handle_mailbody(self, data):
        if "\r\n\r\n" not in data:
            return

        headers, message = data.split("\r\n\r\n", 1)
        self.request.message = message

        for header in headers.split("\r\n"):
            if ":" not in header:
                continue

            key, value = header.split(":", 1)
            self.request.headers[key] = value.strip()

    def handle_auth(self, data):
        """
        Determines what kind of authentication type was used
        and tries to collect the credentials based on the used authentication
        type

        http://www.samlogic.net/articles/smtp-commands-reference-auth.htm
        """
        auth_handlers = {
            "plain": self.handle_auth_plain,
            "login": self.handle_auth_login
        }

        if len(data) < 2:
            return

        arg_first = data[1].lower()
        if arg_first not in auth_handlers:
            log.warning("Unknown SMTP authentication type: \'%s\'" % arg_first)
            return

        self.request.auth_type = arg_first

        if len(data) > 2:
            auth_handlers[arg_first](data[2])

    def handle_auth_plain(self, arg):
        try:
            user_pass = filter(None, arg.decode("base64").split("\x00"))
            if len(user_pass) < 2:
                return

            self.request.username = user_pass[0]
            self.request.password = user_pass[1]
        except binascii.Error:
            return

    def handle_auth_login(self, arg):
        try:
            self.request.username = arg.decode("base64")
        except binascii.Error:
            return

    def handle_auth_cram_md5(self, arg):
        try:
            data = arg.decode("base64").split(None, 1)
        except binascii.Error:
            return

        if len(data) == 2:
            self.request.username = data[0]

    def handle_auth_login_serv_response(self, data):
        if "UGFzc3dvcmQ6" in self.message:
            try:
                self.request.password = data.decode("base64")
            except binascii.Error:
                return
        elif "VXNlcm5hbWU6" in self.message:
            try:
                self.request.username = data.decode("base64")
            except binascii.Error:
                return

    def handle_auth_serv_response(self, data):
        """
        If not all credentials were passed as an argument to an auth
        command, they will be later sent when the server requests them. If
        that happens, this function extracts them
        """
        handlers = {
            "plain": self.handle_auth_plain,
            "login": self.handle_auth_login_serv_response,
            "cram-md5": self.handle_auth_cram_md5,
        }

        if data and self.request.auth_type in handlers:
            handlers[self.request.auth_type](data[0])

    def parse_request(self, request):
        """"
        Parses the requests sent by an smtp client. Values are stored in
        a SmtpRequest object.
        """
        self.request.raw.append(request)

        if self.command != "data":
            data = request.split(None)
        else:
            data = request

        if not data:
            return

        cmd = data[0].lower()

        # If no valid command is found, see if there are
        # any actions to be performed for the last received response code
        if cmd not in self._commands and cmd not in self._unimplemented:
            if self.rescode in self._res_codes:
                self._res_codes[self.rescode](data)
            return

        self.command = cmd
        if cmd in self._commands:
            self._commands[cmd](data)

    def parse_reply(self, reply):
        """
        Parses the response sent by an smtp server. Values are stored in
        a SmtpReply object
        """
        self.reply.raw.append(reply)

        if len(reply) < 3:
            return

        code = reply[:3]
        self.message = reply

        if code.isdigit() and int(code) >= 100 and int(code) < 600:
            self.rescode = int(code)

            if self.rescode == 250:
                self.reply.ok_responses.extend(filter(None, reply.split("\r\n")))
            elif self.rescode == 220:
                self.reply.ready_message = reply

class SmtpRequest(object):
    def __init__(self):
        self.hostname = None
        self.password = None
        self.username = None
        self.auth_type = None
        self.mail_from = []
        self.message = None
        self.mail_to = []
        self.headers = {}
        self.raw = []

class SmtpReply(object):
    def __init__(self):
        self.ready_message = None
        self.ok_responses = []
        self.raw = []
