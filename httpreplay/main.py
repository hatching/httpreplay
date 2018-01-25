# Copyright (C) 2015-2018 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import click
import io
import logging

from httpreplay.cut import http_handler, https_handler, smtp_handler
from httpreplay.misc import read_tlsmaster
from httpreplay.reader import PcapReader
from httpreplay.smegma import TCPPacketStreamer

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
        from netlib.exceptions import HttpException
        from netlib.http import http1
    except ImportError:
        log.warning(
            "In order to use this utility it is required to have the "
            "mitmproxy tool installed (`pip install httpreplay[mitmproxy]`)"
        )
        raise click.Abort

    if tlsmaster:
        tlsmaster = read_tlsmaster(tlsmaster)
    else:
        tlsmaster = {}

    handlers = {
        443: lambda: https_handler(tlsmaster),
        4443: lambda: https_handler(tlsmaster),
        "generic": http_handler,
    }

    reader = PcapReader(pcapfile)
    reader.tcp = TCPPacketStreamer(reader, handlers)
    writer = FlowWriter(mitmfile)

    l = reader.process()
    if not stream:
        # Sort the http/https requests and responses by their timestamp.
        l = sorted(l, key=lambda x: x[1])

    for s, ts, protocol, sent, recv in l:
        if protocol not in ("http", "https"):
            continue

        srcip, srcport, dstip, dstport = s

        client_conn = models.ClientConnection.make_dummy((srcip, srcport))
        client_conn.timestamp_start = ts

        server_conn = models.ServerConnection.make_dummy((dstip, dstport))
        server_conn.timestamp_start = ts

        flow = models.HTTPFlow(client_conn, server_conn)

        try:
            sent = io.BytesIO(sent.raw)
            request = http1.read_request_head(sent)
            body_size = http1.expected_http_body_size(request)
            request.data.content = "".join(http1.read_body(sent, body_size, None))
        except HttpException as e:
            log.warning("Error parsing HTTP request: %s", e)
            continue

        flow.request = models.HTTPRequest.wrap(request)
        flow.request.host = dstip
        flow.request.port = dstport
        flow.request.scheme = protocol

        try:
            recv = io.BytesIO(recv.raw)
            response = http1.read_response_head(recv)
            body_size = http1.expected_http_body_size(request, response)
            response.data.content = "".join(http1.read_body(recv, body_size, None))
            flow.response = models.HTTPResponse.wrap(response)
        except HttpException as e:
            log.warning("Error parsing HTTP response: %s", e)
            # Fall through (?)

        writer.add(flow)
