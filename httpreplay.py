import argparse
import dpkt
import re
import socket
import tlslite

MASTER_SECRETS = {}
MASTER_SECRET_RE = [
    "RSA Session-ID:([0-9a-f]+) Master-Key:([0-9a-f]+)",
]

class TCPPacketStreamer(object):
    """Iterates over a PCAP file and yields TCP packet streams with support
    for out-of-order packets and all that. Finalizes with a None sentinal for
    both client and server streams to indicate their end."""

    def __init__(self, path):
        self.pcap = dpkt.pcap.Reader(open(path, "rb"))
        self.streams = {}
        self.seq = {}

    def _stream(self, ip, reverse=False):
        ipsrc = socket.inet_ntoa(ip.src)
        ipdst = socket.inet_ntoa(ip.dst)
        if reverse:
            return (ipdst, ip.data.dport), (ipsrc, ip.data.sport)
        else:
            return (ipsrc, ip.data.sport), (ipdst, ip.data.dport)

    def _queue_packet(self, send, stream, tcp):
        chunks = []
        uniqid = send, stream

        # Incoming data also has to be registered.
        if self.streams[uniqid] is None:
            self.streams[uniqid] = tcp.seq

        if tcp.seq == self.streams[uniqid]:
            chunks.append(tcp.data)

            self.streams[uniqid] += len(tcp.data)
            while (uniqid, self.streams[uniqid]) in self.seq:
                chunks.append(self.seq.pop((uniqid, self.streams[uniqid])))
                self.streams[uniqid] += len(chunks[-1])
        else:
            self.seq[uniqid, tcp.seq] = tcp.data

        return stream, send, "".join(chunks)

    def __iter__(self):
        for ts, packet in self.pcap:
            eth = dpkt.ethernet.Ethernet(packet)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue

            is_rst = ip.data.flags & dpkt.tcp.TH_RST
            is_fin = ip.data.flags & dpkt.tcp.TH_FIN
            if not ip.data.data and not is_rst and not is_fin:
                continue

            stream = self._stream(ip)
            if (True, stream) in self.streams:
                if is_rst:
                    yield stream, True, None
                    yield stream, False, None
                elif is_fin:
                    yield stream, True, None
                else:
                    yield self._queue_packet(True, stream, ip.data)

                continue

            stream_rev = self._stream(ip, reverse=True)
            if (False, stream_rev) in self.streams:
                if is_rst:
                    yield stream, True, None
                    yield stream, False, None
                elif is_fin:
                    yield stream_rev, False, None
                else:
                    yield self._queue_packet(False, stream_rev, ip.data)

                continue

            self.streams[True, stream] = ip.data.seq + len(ip.data.data)
            self.streams[False, stream] = None
            yield stream, True, ip.data.data

class TCPStream(object):
    """Concatenates TCP streams into ask/response sequences and transparently
    yields single TLS records if requested to do so."""

    def __init__(self, ((ipsrc, sport), (ipdst, dport)), tls=False):
        self.ipsrc = ipsrc
        self.sport = sport
        self.ipdst = ipdst
        self.dport = dport
        self.tls = tls
        self.packets = []

    def put_packet(self, send, packet):
        if self.packets and packet is not None:
            last_send, last_packet = self.packets[-1]
            if last_send == send:
                self.packets[-1] = last_send, last_packet + packet
                return

        self.packets.append((send, packet))

    def pop_packet(self, send=None):
        send_packet, packet = self.packets.pop(0)
        if send is not None:
            assert send == send_packet
            return packet
        else:
            return send_packet, packet

    def pop_tls_record(self, send=None):
        send_packet, packet = self.packets.pop(0)
        if send is not None:
            assert send == send_packet

        if packet is None:
            return send_packet, packet

        record = dpkt.ssl.TLSRecord(packet)
        if len(packet) > len(record):
            self.packets.insert(0, (send_packet, packet[len(record):]))

        if send is None:
            return send_packet, record
        else:
            return record

    def __iter__(self):
        while self.packets:
            if self.tls:
                send, record = self.pop_tls_record()
            else:
                send, record = self.pop_packet()

            if record is None:
                continue

            yield send, record

class TLSStream(tlslite.tlsrecordlayer.TLSRecordLayer):
    """Decrypts TLS streams into a TCPStream-like session."""

    _tls_versions = {
        dpkt.ssl.SSL3_V: (3, 0),
        dpkt.ssl.TLS1_V: (3, 1),
        dpkt.ssl.TLS11_V: (3, 2),
        dpkt.ssl.TLS12_V: (3, 3),
    }

    def _parse_record(self, record):
        if record.type not in dpkt.ssl.RECORD_TYPES:
            raise dpkt.ssl.SSL3Exception("Invalid record type: %d", record.type)

        return dpkt.ssl.RECORD_TYPES[record.type](record.data)

    def init_cipher(self, tls_version, cipher_suite, master_secret,
                    client_random, server_random, cipher_implementations):
        self._client = True
        self.version = self._tls_versions[tls_version]

        self._calcPendingStates(cipher_suite, master_secret, client_random,
                                server_random, cipher_implementations)

        self.server_cipher = self._pendingReadState
        self.client_cipher = self._pendingWriteState

    def decrypt_server(self, record_type, buf):
        self._readState = self.server_cipher
        return str(next(self._decryptRecord(record_type, bytearray(buf))))

    def decrypt_client(self, record_type, buf):
        self._readState = self.client_cipher
        return str(next(self._decryptRecord(record_type, bytearray(buf))))

    def decrypt(self, send, record_type, buf):
        fn = self.decrypt_client if send else self.decrypt_server
        return fn(record_type, buf)

    def __iter__(self):
        client_hello = self._parse_record(self.sock.pop_tls_record(True))
        server_hello = self._parse_record(self.sock.pop_tls_record(False))
        master_secret = MASTER_SECRETS[server_hello.data.session_id]

        self.init_cipher(client_hello.data.version,
                         server_hello.data.cipher_suite, master_secret,
                         client_hello.data.random, server_hello.data.random,
                         tlslite.handshakesettings.CIPHER_IMPLEMENTATIONS)

        if not client_hello.data.session_id:
            record = self._parse_record(self.sock.pop_tls_record(False))
            if not isinstance(record, dpkt.ssl.TLSHandshake):
                raise dpkt.ssl.SSL3Exception("Expected certificate handshake")

            record = self._parse_record(self.sock.pop_tls_record(False))
            if not isinstance(record, dpkt.ssl.TLSHandshake):
                raise dpkt.ssl.SSL3Exception("Expected server hello done")

            record = self._parse_record(self.sock.pop_tls_record(True))
            if not isinstance(record, dpkt.ssl.TLSHandshake):
                raise dpkt.ssl.SSL3Exception("Expected client key exchange")

        # This is pretty ugly, but basically we have to retrieve two "Change
        # Cipher Spec" messages and two "Finished" messages (one for the
        # client and one for the server). The order of these messages is not
        # specified, so here we go..
        for idx in xrange(4):
            send, record = self.sock.pop_tls_record()

            # Indicates the "Change Cipher Spec" message.
            if record.type == 20 and len(record.data) == 1:
                continue

            self.decrypt(send, record.type, record.data)

        # Stream the TLS stream as if it was a regular TCP stream.
        self.sock.tls = True
        for send, record in self.sock:
            packet = self._parse_record(record)

            if send:
                yield send, self.decrypt_client(record.type, packet)
            else:
                yield send, self.decrypt_server(record.type, packet)

class HttpStream(object):
    def __init__(self, pcapfile):
        self.pcapfile = pcapfile

    def __iter__(self):
        streams = {}
        for stream, send, packet in TCPPacketStreamer(self.pcapfile):
            if stream not in streams:
                pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcapfile", type=str)
    parser.add_argument("tlsmaster", type=str)
    args = parser.parse_args()

    for line in open(args.tlsmaster, "rb"):
        for master_re in MASTER_SECRET_RE:
            group = re.match(master_re, line)
            if group:
                session_id, master_key = group.groups()
                MASTER_SECRETS[session_id.decode("hex")] = \
                    master_key.decode("hex")

    sockets = {}
    socks = []
    for stream, send, packet in TCPPacketStreamer(args.pcapfile):
        if stream not in sockets:
            sockets[stream] = TCPStream(stream)
            socks.append(sockets[stream])

        if packet is not None:
            sockets[stream].put_packet(send, packet)

    for sock in socks:
        for x in TLSStream(sock):
            print repr(x)
