# Copyright (C) 2015 Jurriaan Bremer <jbr@cuckoo.sh>
# This file is part of HTTPReplay - http://jbremer.org/httpreplay/
# See the file 'LICENSE' for copying permission.

class Protocol(object):
    def __init__(self, parent=None, *args, **kwargs):
        self.parent = parent
        self.init(*args, **kwargs)

    def init(self, *args, **kwargs):
        pass

    def handle(self, s, ts, protocol, sent, recv):
        pass
