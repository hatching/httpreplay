import logging
from io import BytesIO

import click

from httpreplay.cut import (
    http_handler, https_handler, smtp_handler
)
from httpreplay.reader import PcapReader
from httpreplay.smegma import TCPPacketStreamer, TLSStream
from httpreplay.misc import read_tlsmaster
from httpreplay.shoddy import Protocol

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@click.command()
@click.argument("pcapfile", type=click.File("rb"))
@click.option("--tlsmaster", type=click.Path(file_okay=True), help="TLS master secrets file")
def httpreplay(pcapfile, tlsmaster):

    if tlsmaster:
        tls_master_secrets = read_tlsmaster(tlsmaster)
    else:
        tls_master_secrets = {}

    handlers = {
        25: smtp_handler,
        80: http_handler,
        8000: http_handler,
        8080: http_handler,
        443: lambda: https_handler(tls_master_secrets),
        4443: lambda: https_handler(tls_master_secrets),
    }

    reader = PcapReader(pcapfile)
    reader.tcp = TCPPacketStreamer(reader, handlers)

    for s, ts, protocol, sent, recv in reader.process():
        print s, "%f" % ts, protocol, getattr(sent, "uri", None)


@click.command()
@click.argument("pcapfile", type=click.File("rb"))
@click.argument("mitmfile", type=click.File("wb"))
@click.option("--tlsmaster", type=click.Path(file_okay=True), help="TLS master secrets file")
@click.option("--stream/--no-stream", default=False)
def pcap2mitm(pcapfile, mitmfile, tlsmaster, stream):
    try:
        from mitmproxy import models
        from mitmproxy.flow import FlowWriter
        from netlib.http import http1
        from netlib.exceptions import HttpException
    except ImportError:
        raise click.Abort(
            "In order to use this utility it is required to have the "
            "mitmproxy tool installed (`pip install httpreplay[mitmproxy]`)"
        )

    class NetlibHttpProtocol(Protocol):
        """
        Like HttpProtocol, but actually covering edge-cases.
        """

        @staticmethod
        def read_body(io, expected_size):
            """
            Read a (malformed) HTTP body.
            Returns:
                A (body: bytes, is_malformed: bool) tuple.
            """
            body_start = io.tell()
            try:
                content = b"".join(http1.read_body(io, expected_size, None))
                if io.read():  # leftover?
                    raise HttpException()
                return content, False
            except HttpException:
                io.seek(body_start)
                return io.read(), True

        def parse_request(self, ts, sent):
            try:
                sent = BytesIO(sent)
                request = http1.read_request_head(sent)
                body_size = http1.expected_http_body_size(request)
                request.data.content, malformed = self.read_body(sent, body_size)
                if malformed:
                    request.headers["X-Mitmproxy-Malformed-Body"] = "1"
                return request
            except HttpException as e:
                log.warning("{!r} (timestamp: {})".format(e, ts))

        def parse_response(self, ts, recv, request):
            try:
                recv = BytesIO(recv)
                response = http1.read_response_head(recv)
                body_size = http1.expected_http_body_size(request, response)
                response.data.content, malformed = self.read_body(recv, body_size)
                if malformed:
                    response.headers["X-Mitmproxy-Malformed-Body"] = "1"
                return response
            except HttpException as e:
                log.warning("{!r} (timestamp: {})".format(e, ts))

        def handle(self, s, ts, protocol, sent, recv):
            if protocol not in ("tcp", "tls"):
                self.parent.handle(s, ts, protocol, sent, recv)
                return

            req = None
            if sent:
                req = self.parse_request(ts, sent)

            protocols = {
                "tcp": "http",
                "tls": "https",
            }

            # Only try to decode the HTTP response if the request was valid HTTP.
            if req:
                res = self.parse_response(ts, recv, req)

                # Report this stream as being a valid HTTP stream.
                self.parent.handle(s, ts, protocols[protocol],
                                   req or sent, res)
            else:
                # This wasn't a valid HTTP stream so we forward the original TCP
                # or TLS stream straight ahead to our parent.
                self.parent.handle(s, ts, protocol, sent, recv)

    if tlsmaster:
        tlsmaster = read_tlsmaster(tlsmaster)
    else:
        tlsmaster = {}

    netlib_http_handler = lambda: NetlibHttpProtocol()
    netlib_https_handler = lambda: TLSStream(NetlibHttpProtocol(), tlsmaster)
    handlers = {
        443: netlib_https_handler,
        4443: netlib_https_handler,
        "generic": netlib_http_handler,
    }

    reader = PcapReader(pcapfile)
    reader.tcp = TCPPacketStreamer(reader, handlers)
    writer = FlowWriter(mitmfile)

    l = reader.process()
    if not stream:
        # Sort the http/https requests and responses by their timestamp.
        l = sorted(l, key=lambda x: x[1])

    for addrs, timestamp, protocol, sent, recv in l:
        if protocol not in ("http", "https"):
            continue

        srcip, srcport, dstip, dstport = addrs

        client_conn = models.ClientConnection.make_dummy((srcip, srcport))
        client_conn.timestamp_start = timestamp

        server_conn = models.ServerConnection.make_dummy((dstip, dstport))
        server_conn.timestamp_start = timestamp

        flow = models.HTTPFlow(client_conn, server_conn)

        flow.request = models.HTTPRequest.wrap(sent)
        flow.request.host, flow.request.port = dstip, dstport
        flow.request.scheme = protocol
        if recv:
            flow.response = models.HTTPResponse.wrap(recv)

        writer.add(flow)
