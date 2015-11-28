# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

class ReplayException(Exception):
    """Generic HTTPReplay exception."""

class UnknownDatalink(ReplayException):
    """Unknown PCAP Datalink exception."""

class UnknownEthernetProtocol(ReplayException):
    """Unknown Ethernet Protocol exception."""

class UnknownIpProtocol(ReplayException):
    """Unknown IP Protocol exception."""

class UnknownTcpSequenceNumber(ReplayException):
    """Unknown TCP sequence number exception."""

class InvalidTcpPacketOrder(ReplayException):
    """Invalid TCP packet received at this point."""

class UnexpectedTcpData(ReplayException):
    """The TCP packet contained content data we did not expect."""

class UnknownHttpEncoding(ReplayException):
    """Unknown HTTP content encoding."""
