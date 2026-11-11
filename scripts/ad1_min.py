#!/usr/bin/env python3
"""Minimal read-only AD1 (AccessData logical image, single segment, v4) reader.
Usage:
  python3 -I ad1_min.py IMAGE.ad1 list            -> tree: path, size, type, key metadata
  python3 -I ad1_min.py IMAGE.ad1 extract OUTDIR   -> extract all files under OUTDIR
  python3 -I ad1_min.py IMAGE.ad1 cat /path/in/image
Layout (reverse engineered): segment header 0x200 bytes; addresses are relative to 0x200.
Item: next u64, child u64, meta u64, zlib_base u64, size u64, type u32, name_len u32, name,
      [file data] unk u64, num_chunks u64, (num_chunks+1) x u64 chunk offsets (zlib chunks of 0x10000).
Meta: next u64, category u32, type u32, len u32, data.
"""
import sys, struct, zlib, os

BASE = 0x200
META_NAMES = {
    (1, 0x5001): 'MD5', (1, 0x5002): 'SHA1',
    (3, 0x01): 'Access', (3, 0x02): 'Modified', (3, 0x03): 'Changed',
    (5, 0x08): 'Atime', (5, 0x09): 'Ctime', (5, 0x0a): 'Mtime', (5, 0x0b): 'Btime',
}


class AD1:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        assert self.d[:15] == b'ADSEGMENTEDFILE'
        assert self.d[BASE:BASE + 14] == b'ADLOGICALIMAGE'
        i = self.d.find(b'\x06\x00\x00\x00[root]')
        self.first = i - 44 - BASE  # item header starts 44 bytes before name_len (5 x u64 + type u32)

    def u64(self, o):
        return struct.unpack_from('<Q', self.d, o)[0]

    def u32(self, o):
        return struct.unpack_from('<I', self.d, o)[0]

    def item(self, addr):
        o = addr + BASE
        nxt, child, meta, zbase, size = struct.unpack_from('<QQQQQ', self.d, o)
        typ, nl = struct.unpack_from('<II', self.d, o + 40)
        name = self.d[o + 48:o + 48 + nl].decode('utf-8', 'replace')
        p = o + 48 + nl
        chunks = []
        if size:
            unk, n = struct.unpack_from('<QQ', self.d, p)
            chunks = list(struct.unpack_from('<%dQ' % (n + 1), self.d, p + 16))
        return dict(next=nxt, child=child, meta=meta, size=size, type=typ, name=name, chunks=chunks, addr=addr)

    def metas(self, addr):
        out = []
        while addr:
            o = addr + BASE
            nxt, cat, typ, ln = struct.unpack_from('<QIII', self.d, o)
            data = self.d[o + 20:o + 20 + ln].decode('utf-8', 'replace')
            out.append((cat, typ, data))
            addr = nxt
        return out

    def data(self, it):
        if not it['size']:
            return b''
        out = bytearray()
        ch = it['chunks']
        for i in range(len(ch) - 1):
            raw = self.d[ch[i] + BASE:ch[i + 1] + BASE]
            try:
                out += zlib.decompress(raw)
            except Exception:
                out += zlib.decompressobj().decompress(raw)
        return bytes(out[:it['size']])

    def walk(self, addr=None, prefix=''):
        addr = self.first if addr is None else addr
        while addr:
            it = self.item(addr)
            path = prefix + '/' + it['name']
            yield path, it
            if it['child']:
                yield from self.walk(it['child'], path)
            addr = it['next']


def main():
    a = AD1(sys.argv[1])
    cmd = sys.argv[2]
    if cmd == 'list':
        for path, it in a.walk():
            m = a.metas(it['meta']) if it['meta'] else []
            ms = ' '.join('%s=%s' % (META_NAMES.get((c, t), '%d/%x' % (c, t)), v) for c, t, v in m
                          if (c, t) in META_NAMES)
            print('%s\t%d\ttype=%d\t%s' % (path, it['size'], it['type'], ms))
    elif cmd == 'extract':
        out = sys.argv[3]
        for path, it in a.walk():
            dest = os.path.join(out, path.lstrip('/'))
            if it['type'] == 5:
                os.makedirs(dest, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                open(dest, 'wb').write(a.data(it))
    elif cmd == 'cat':
        want = sys.argv[3]
        for path, it in a.walk():
            if path == want:
                sys.stdout.buffer.write(a.data(it))
                return
        sys.exit('not found')
    elif cmd == 'meta':
        want = sys.argv[3]
        for path, it in a.walk():
            if path == want:
                for c, t, v in a.metas(it['meta']):
                    print(c, hex(t), v)


if __name__ == '__main__':
    main()
