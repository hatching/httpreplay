# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import re
import binascii

_hexdecode = binascii.a2b_hex

tlsmaster1 = "RSA Session-ID:(?P<sid>[0-9a-f]+) Master-Key:(?P<key>[0-9a-f]+)"
tlsmaster2 = "CLIENT_RANDOM (?P<sid>[0-9a-f]+) (?P<key>[0-9a-f]+)"

def read_tlsmaster(filepath):
    ret = {}
    for line in open(filepath, "r"):
        x = re.match(tlsmaster1, line)
        if x:
            sid = x.group("sid").strip()
            key = x.group("key").strip()
            ret[binascii.a2b_hex(sid)] = binascii.a2b_hex(key)
        x = re.match(tlsmaster2, line)
        if x:
            sid = x.group("sid").strip()
            key = x.group("key").strip()
            ret[binascii.a2b_hex(sid)] = binascii.a2b_hex(key)
    return ret
