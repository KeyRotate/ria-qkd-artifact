#!/usr/bin/env python3
import struct, sys
for path in sys.argv[1:]:
    try:
        data = open(path, "rb").read()
    except Exception as e:
        print(path, "error:", e); continue
    idx = data.find(b"HASH")
    if idx >= 0 and idx + 16 <= len(data):
        m, c, a, d = struct.unpack(">IIII", data[idx:idx + 16])
        print("%s: magic=0x%08x cycles=%d (%.1f ms @168MHz) accepted=%d done=%d"
              % (path, m, c, c / 168e3, a, d))
    else:
        print("%s: no results frame (%d bytes)" % (path, len(data)))
