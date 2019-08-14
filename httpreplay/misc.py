# Copyright (C) 2015-2019 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import dpkt
import hashlib
import re
import struct

tlsmaster = "RSA Session-ID:(?P<sid>[0-9a-f]+) Master-Key:(?P<key>[0-9a-f]+)"

def read_tlsmaster(filepath):
    ret = {}
    for line in open(filepath, "rb"):
        x = re.match(tlsmaster, line)
        if x:
            sid = x.group("sid").strip()
            key = x.group("key").strip()
            ret[sid.decode("hex")] = key.decode("hex")
    return ret

class JA3(object):
    """This JA3/JA3S calculation code is a modified version of the code
    found at: https://github.com/salesforce/ja3"""

    GREASE_TABLE = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
                    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                    0xcaca, 0xdada, 0xeaea, 0xfafa]

    @staticmethod
    def JA3(client_hello):
        if not isinstance(client_hello, dpkt.ssl.TLSClientHello):
            raise ValueError(
                "Expected TLSClientHello, got %s", type(client_hello)
            )

        ja3_params = ",".join(JA3._handle_client_hello(client_hello))
        return hashlib.md5(ja3_params.encode()).hexdigest(), ja3_params

    @staticmethod
    def JA3S(server_hello):
        if not isinstance(server_hello, dpkt.ssl.TLSServerHello):
            raise ValueError(
                "Expected TLSServerHello, got %s", type(server_hello)
            )

        ja3_params = ",".join(JA3._handle_server_hello(server_hello))
        return hashlib.md5(ja3_params.encode()).hexdigest(), ja3_params

    @staticmethod
    def _handle_client_hello(handshake):
        ja3 = [str(handshake.version)]
        buf, ptr = JA3._parse_variable_array(handshake.data, 1)
        buf, ptr = JA3._parse_variable_array(handshake.data[ptr:], 2)
        ja3.append(JA3._convert_to_ja3_segment(buf, 2))
        ja3 += JA3._process_extensions(handshake)
        return ja3

    @staticmethod
    def _handle_server_hello(handshake):
        ja3 = [str(handshake.version)]
        ja3.append(str(handshake.cipher_suite))
        ja3 += JA3._process_extensions_server(handshake)
        return ja3

    @staticmethod
    def _process_extensions_server(server_handshake):
        """Process any extra extensions and convert to a JA3 segment.

        :param server_handshake: Handshake data from the packet
        :type server_handshake: dpkt.ssl.TLSServerHello
        :returns: list
        """
        if not hasattr(server_handshake, "extensions"):
            # Needed to preserve commas on the join
            return [""]

        exts = list()
        for ext_val, ext_data in server_handshake.extensions:
            exts.append(ext_val)

        results = list()
        results.append("-".join([str(x) for x in exts]))
        return results

    @staticmethod
    def _process_extensions(client_handshake):
        """Process any extra extensions and convert to a JA3 segment.

        :param client_handshake: Handshake data from the packet
        :type client_handshake: dpkt.ssl.TLSClientHello
        :returns: list
        """
        if not hasattr(client_handshake, "extensions"):
            # Needed to preserve commas on the join
            return ["", "", ""]

        exts = list()
        elliptic_curve = ""
        elliptic_curve_point_format = ""
        for ext_val, ext_data in client_handshake.extensions:
            if ext_val not in JA3.GREASE_TABLE:
                exts.append(ext_val)
            if ext_val == 0x0a:
                a, b = JA3._parse_variable_array(ext_data, 2)
                # Elliptic curve points (16 bit values)
                elliptic_curve = JA3._convert_to_ja3_segment(a, 2)
            elif ext_val == 0x0b:
                a, b = JA3._parse_variable_array(ext_data, 1)
                # Elliptic curve point formats (8 bit values)
                elliptic_curve_point_format = JA3._convert_to_ja3_segment(a, 1)
            else:
                continue

        results = list()
        results.append("-".join([str(x) for x in exts]))
        results.append(elliptic_curve)
        results.append(elliptic_curve_point_format)
        return results

    @staticmethod
    def _ntoh(buf):
        """Convert to network order.

        :param buf: Bytes to convert
        :type buf: bytearray
        :returns: int
        """
        if len(buf) == 1:
            return buf[0]
        elif len(buf) == 2:
            return struct.unpack('!H', buf)[0]
        elif len(buf) == 4:
            return struct.unpack('!I', buf)[0]
        else:
            raise ValueError('Invalid input buffer size for NTOH')

    @staticmethod
    def _parse_variable_array(buf, byte_len):
        """Unpack data from buffer of specific length.

        :param buf: Buffer to operate on
        :type buf: bytes
        :param byte_len: Length to process
        :type byte_len: int
        :returns: bytes, int
        """
        _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
        assert byte_len <= 4
        size_format = _SIZE_FORMATS[byte_len - 1]
        padding = b'\x00' if byte_len == 3 else b''
        size = struct.unpack(size_format, padding + buf[:byte_len])[0]
        data = buf[byte_len:byte_len + size]

        return data, size + byte_len

    @staticmethod
    def _convert_to_ja3_segment(data, element_width):
        """Convert a packed array of elements to a JA3 segment.

        :param data: Current PCAP buffer item
        :type: str
        :param element_width: Byte count to process at a time
        :type element_width: int
        :returns: str
        """
        int_vals = list()
        data = bytearray(data)
        if len(data) % element_width:
            message = '{count} is not a multiple of {width}'
            message = message.format(count=len(data), width=element_width)
            raise ValueError(message)

        for i in range(0, len(data), element_width):
            element = JA3._ntoh(data[i: i + element_width])
            if element not in JA3.GREASE_TABLE:
                int_vals.append(element)

        return "-".join(str(x) for x in int_vals)


def patch_dpkt_ssl_tlshello_unpacks():
    """Patch dpkt to be able to get TLS Client/ServerHello extensions. The code
    was taken directly from the dpkt repository. Newer versions than dpkt 1.8.7
    contain this code, but we currently cannot upgrade to a newer version as
    this lead to a large amount of unicode decoding issues."""
    # TODO remove this patch when Python 3 is fully supported by Httpreplay
    # and Cuckoo.
    import dpkt
    import struct

    def _parse_extensions(buf):
        """
        Parse TLS extensions in passed buf. Returns an ordered list of
        extension tuples with ordinal extension type as first value and
        extension data as second value. Passed buf must start with the 2-byte
        extensions length TLV.
        http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
        """
        extensions_length = struct.unpack('!H', buf[:2])[0]
        extensions = []

        pointer = 2
        while pointer < extensions_length:
            ext_type = struct.unpack('!H', buf[pointer:pointer + 2])[0]
            pointer += 2
            ext_data, parsed = dpkt.ssl.parse_variable_array(buf[pointer:], 2)
            extensions.append((ext_type, ext_data))
            pointer += parsed
        return extensions

    class _TLSClientHelloPatched(dpkt.ssl.TLSClientHello):

        __hdr__ = (
            ('version', 'H', 0x0301),
            ('random', '32s', '\x00' * 32),
        )  # the rest is variable-length and has to be done manually

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            # now session, cipher suites, extensions are in self.data
            self.session_id, pointer = dpkt.ssl.parse_variable_array(
                self.data, 1
            )
            # handle ciphersuites
            ciphersuites, parsed = dpkt.ssl.parse_variable_array(
                self.data[pointer:], 2
            )
            pointer += parsed
            self.num_ciphersuites = len(ciphersuites) / 2
            # check len(ciphersuites) % 2 == 0 ?
            # compression methods
            compression_methods, parsed = dpkt.ssl.parse_variable_array(
                self.data[pointer:], 1
            )
            pointer += parsed
            self.num_compression_methods = parsed - 1
            self.compression_methods = map(ord, compression_methods)
            # Parse extensions if present
            if len(self.data[pointer:]) >= 6:
                self.extensions = dpkt.ssl.parse_extensions(
                    self.data[pointer:]
                )

    class _TLSServerHelloPatched(dpkt.ssl.TLSServerHello):
        __hdr__ = (
            ('version', 'H', '0x0301'),
            ('random', '32s', '\x00' * 32),
        )  # session is variable, forcing rest to be manual

        def unpack(self, buf):
            try:
                dpkt.Packet.unpack(self, buf)
                self.session_id, pointer = dpkt.ssl.parse_variable_array(
                    self.data, 1
                )
                # single cipher suite
                self.cipher_suite = struct.unpack(
                    '!H', self.data[pointer:pointer + 2]
                )[0]
                pointer += 2
                # single compression method
                self.compression = \
                struct.unpack('!B', self.data[pointer:pointer + 1])[0]
                pointer += 1
                # Parse extensions if present
                if len(self.data[pointer:]) >= 6:
                    self.extensions = dpkt.ssl.parse_extensions(
                        self.data[pointer:]
                    )
            except struct.error:
                # probably data too short
                raise dpkt.NeedData

    dpkt.ssl.TLSClientHello = _TLSClientHelloPatched
    dpkt.ssl.TLSServerHello = _TLSServerHelloPatched
    dpkt.ssl.parse_extensions = _parse_extensions
    dpkt.ssl.HANDSHAKE_TYPES[1] = ('ClientHello', _TLSClientHelloPatched)
    dpkt.ssl.HANDSHAKE_TYPES[2] = ('ServerHello', _TLSServerHelloPatched)
