# Copyright (C) 2015-2021 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import socket
from collections import namedtuple

import dpkt

from .abstracts import Protocol

DNSQuery = namedtuple("DNSQuery", ["type", "name"])
DNSResponse = namedtuple("DNSResponse", ["type", "data", "fields"])

class DNSQueries:

    __slots__ = ("queries", "rawsize")

    def __init__(self, queries, raw):
        self.queries = queries
        self.rawsize = len(raw)

    def __len__(self):
        return self.rawsize

class DNSResponses:

    __slots__ = ("responses", "queries", "rawsize")

    def __init__(self, responses, queries, raw):
        self.responses = responses
        self.queries = queries
        self.rawsize = len(raw)

    def __len__(self):
        return self.rawsize

_TYPE_MAP = {
    dpkt.dns.DNS_A: "A",
    dpkt.dns.DNS_NS: "NS",
    dpkt.dns.DNS_CNAME: "CNAME",
    dpkt.dns.DNS_SOA: "SOA",
    dpkt.dns.DNS_NULL: "NULL",
    dpkt.dns.DNS_PTR: "PTR",
    dpkt.dns.DNS_HINFO: "HINFO",
    dpkt.dns.DNS_MX: "MX",
    dpkt.dns.DNS_TXT: "TXT",
    dpkt.dns.DNS_AAAA: "AAAA",
    dpkt.dns.DNS_SRV: "SRV",
    dpkt.dns.DNS_OPT: "OPT",
    dpkt.dns.DNS_ANY: "ANY"
}

def _get_ip(data):
    try:
        return socket.inet_ntop(socket.AF_INET, data)
    except ValueError:
        try:
            return socket.inet_ntop(socket.AF_INET6, data)
        except ValueError:
            return str(data)

class DNS(Protocol):

    def _make_dns_response(self, dns, rawdata):
        if dns.opcode != dpkt.dns.DNS_QUERY:
            return

        if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
            return

        # No DNS queries in the DNS response
        if not dns.qd:
            return

        # No answers in the DNS response
        if not dns.an:
            return

        queries = []
        for entry in dns.qd:
            queries.append(DNSQuery(
                type=_TYPE_MAP.get(entry.type, "Unknown"), name=entry.name
            ))

        answers = []
        for ans in dns.an:
            data = None
            fields = {}
            if ans.type in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA):
                data = _get_ip(ans.rdata)
            elif ans.type == dpkt.dns.DNS_CNAME:
                data = ans.cname
            elif ans.type == dpkt.dns.DNS_PTR:
                data = ans.ptrname
            elif ans.type == dpkt.dns.DNS_NS:
                data = ans.nsname
            elif ans.type in (dpkt.dns.DNS_HINFO, dpkt.dns.DNS_TXT):
                data = " ".join(ans.text)
            elif ans.type == dpkt.dns.DNS_MX:
                data = ans.mxname
                fields = {
                    "preference": ans.preference[0]
                }
            elif ans.type == dpkt.dns.DNS_SOA:
                data = ans.mname
                fields = {
                    "rname": ans.rname,
                    "serial": ans.serial,
                    "refresh": ans.refresh,
                    "retry": ans.retry,
                    "expire": ans.expire,
                    "minimum": ans.minimum
                }
            elif ans.type == dpkt.dns.DNS_SRV:
                data = ans.srvname
                fields = {
                    "priority": ans.priority,
                    "weight": ans.weight,
                    "port": ans.port
                }

            answers.append(DNSResponse(
                type=_TYPE_MAP.get(ans.type, "Unknown"), data=data,
                fields=fields
            ))

        return DNSResponses(
            responses=answers, queries=queries, raw=rawdata
        )

    def _make_dns_query(self, dns, rawdata):
        if dns.opcode != dpkt.dns.DNS_QUERY:
            return
        if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
            return

        # No DNS queries in the DNS response
        if not dns.qd:
            return

        queries = []
        for entry in dns.qd:
            queries.append(DNSQuery(
                type=_TYPE_MAP.get(entry.type, "Unknown"), name=entry.name
            ))

        return DNSQueries(queries=queries, raw=rawdata)

    def handle(self, s, ts, protocol, sent, recv=None, tlsinfo=None):
        if protocol != "udp":
            self.parent.handle(s, ts, protocol, sent, recv, tlsinfo)
            return

        try:
            dns = dpkt.dns.DNS(sent)
        except (dpkt.UnpackError, UnicodeDecodeError):
            self.parent.handle(s, ts, protocol, sent, recv, tlsinfo)
            return

        # For now, only process query response. Later expand to keep track
        # of the actual query and response and yield when we have both of them
        if dns.qr == dpkt.dns.DNS_R:
            responses = self._make_dns_response(dns, sent)
            if responses:
                self.parent.handle(s, ts, "dns", responses, None, tlsinfo)

        elif dns.qr == dpkt.dns.DNS_Q:
            queries = self._make_dns_query(dns, sent)
            if queries:
                self.parent.handle(s, ts, "dns", queries, None, tlsinfo)
