# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

import re

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
