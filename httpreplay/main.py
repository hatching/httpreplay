# Copyright (C) 2015-2018 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import click
import logging

from httpreplay.cut import http_handler, https_handler, smtp_handler
from httpreplay.misc import read_tlsmaster
from httpreplay.reader import PcapReader
from httpreplay.smegma import TCPPacketStreamer
from httpreplay.utils import pcap2mitm

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
def do_pcap2mitm(pcapfile, mitmfile, tlsmaster, stream):
    if pcap2mitm(pcapfile, mitmfile, tlsmaster, stream) is False:
        raise click.Abort
