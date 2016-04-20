import logging
from io import BytesIO

import click

from httpreplay.cut import (
    http_handler, https_handler, smtp_handler
)
from httpreplay.reader import PcapReader
from httpreplay.smegma import TCPPacketStreamer
from httpreplay.misc import read_tlsmaster

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
@click.option('--stream/--no-stream', default=False)
def pcap2mitm(pcapfile, mitmfile, tlsmaster, stream):
    try:
        from mitmproxy import models
        from mitmproxy.flow import FlowWriter
        from netlib.http import http1
        from netlib.exceptions import HttpSyntaxException
    except ImportError:
        raise click.Abort(
            "In order to use this utility it is required to have the "
            "mitmproxy tool installed (`pip install httpreplay[mitmproxy]`)"
        )

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
                raise HttpSyntaxException()
            return content, False
        except HttpSyntaxException:
            io.seek(body_start)
            return io.read(), True

    if tlsmaster:
        tlsmaster = read_tlsmaster(tlsmaster)
    else:
        tlsmaster = {}

    handlers = {
        80: http_handler,
        8000: http_handler,
        8080: http_handler,
        443: lambda: https_handler(tlsmaster),
        4443: lambda: https_handler(tlsmaster),
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

        # We need to manually read request and response bodies as the PCAP may
        # be incomplete and we'd complain on an unexpected body length.
        req_io = BytesIO(sent.raw)
        request = http1.read_request_head(req_io)
        request_body_size = http1.expected_http_body_size(request)

        if request_body_size > 0:
            request_body_size = -1

        request.data.content, malformed = read_body(req_io, request_body_size)
        if malformed:
            request.headers["X-Mitmproxy-Malformed-Request-Body"] = "1"

        flow.request = models.HTTPRequest.wrap(request)
        flow.request.host, flow.request.port = dstip, dstport
        flow.request.scheme = protocol

        resp_io = BytesIO(recv.raw)
        response = http1.read_response_head(resp_io)
        response_body_size = http1.expected_http_body_size(request, response)

        if response_body_size > 0:
            response_body_size = -1

        response.data.content, malformed = read_body(resp_io, response_body_size)
        if malformed:
            response.headers["X-Mitmproxy-Malformed-Response-Body"] = "1"

        flow.response = models.HTTPResponse.wrap(response)

        writer.add(flow)