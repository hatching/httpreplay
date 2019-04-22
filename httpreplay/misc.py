# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import re
import codecs
from builtins import str

decode_hex = codecs.getdecoder("hex_codec")

tlsmaster1 = "RSA Session-ID:(?P<sid>[0-9a-f]+) Master-Key:(?P<key>[0-9a-f]+)"
tlsmaster2 = "CLIENT_RANDOM (?P<sid>[0-9a-f]+) (?P<key>[0-9a-f]+)"

def read_tlsmaster(filepath):
    ret = {}
    for line in open(filepath, "r"):
        x = re.match(tlsmaster1, line)
        if x:
            sid = x.group("sid").strip()
            key = x.group("key").strip()
            ret[decode_hex(sid)[0]] = decode_hex(key)[0]
        x = re.match(tlsmaster2, line)
        if x:
            sid = x.group("sid").strip()
            key = x.group("key").strip()
            ret[decode_hex(sid)[0]] = decode_hex(key)[0]
    return ret
