#!/usr/bin/env python3
"""Minimal CFB + jump list DestList parser. Usage: python3 -I jl_min.py file.automaticDestinations-ms"""
import sys, struct, datetime
EPOCH = datetime.datetime(1601,1,1)
def ft(v):
    try: return (EPOCH+datetime.timedelta(microseconds=v//10)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception: return 'bad'
def cfb_streams(d):
    ss = 1 << struct.unpack('<H', d[30:32])[0]
    mss = 1 << struct.unpack('<H', d[32:34])[0]
    firstdir = struct.unpack('<I', d[48:52])[0]
    cutoff = struct.unpack('<I', d[56:60])[0]
    firstmini = struct.unpack('<I', d[60:64])[0]
    nmini = struct.unpack('<I', d[64:68])[0]
    difat = list(struct.unpack('<109I', d[76:76+436]))
    nfat = struct.unpack('<I', d[44:48])[0]
    def sec(n): return d[(n+1)*ss:(n+2)*ss]
    fat = []
    for s in difat[:nfat]:
        if s >= 0xFFFFFFFA: continue
        fat += list(struct.unpack('<%dI' % (ss//4), sec(s)))
    def chain(start):
        out=[]; s=start; seen=set()
        while s < 0xFFFFFFFA and s not in seen:
            seen.add(s); out.append(s); s = fat[s]
        return out
    def read_chain(start): return b''.join(sec(s) for s in chain(start))
    dirdata = read_chain(firstdir)
    ents=[]
    for i in range(0, len(dirdata), 128):
        e = dirdata[i:i+128]
        nl = struct.unpack('<H', e[64:66])[0]
        name = e[:max(nl-2,0)].decode('utf-16le','replace')
        typ = e[66]; start = struct.unpack('<I', e[116:120])[0]; size = struct.unpack('<Q', e[120:128])[0]
        ents.append((name,typ,start,size))
    root = ents[0]
    ministream = read_chain(root[2])[:root[3]]
    minifat = list(struct.unpack('<%dI' % (len(read_chain(firstmini))//4), read_chain(firstmini))) if nmini else []
    out={}
    for name,typ,start,size in ents[1:]:
        if typ != 2: continue
        if size < cutoff:
            data=b''; s=start; seen=set()
            while s < 0xFFFFFFFA and s not in seen:
                seen.add(s); data += ministream[s*mss:(s+1)*mss]; s = minifat[s]
            out[name]=data[:size]
        else:
            out[name]=read_chain(start)[:size]
    return out
def main():
    d = open(sys.argv[1],'rb').read()
    if d[:8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        print('not CFB', len(d)); return
    st = cfb_streams(d)
    print('streams:', {k:len(v) for k,v in st.items()})
    dl = st.get('DestList')
    if dl:
        ver, n, pinned = struct.unpack('<III', dl[:12])
        print('DestList version', ver, 'entries', n, 'pinned', pinned)
        o = 32
        while o + 130 <= len(dl):
            eid = struct.unpack('<I', dl[o+88:o+92])[0]
            mod = struct.unpack('<Q', dl[o+100:o+108])[0]
            pin = struct.unpack('<i', dl[o+108:o+112])[0]
            cnt = struct.unpack('<I', dl[o+116:o+120])[0]
            host = dl[o+72:o+88].split(b'\0')[0].decode('latin1')
            pl = struct.unpack('<H', dl[o+128:o+130])[0]
            path = dl[o+130:o+130+pl*2].decode('utf-16le','replace')
            print('entry', eid, 'count', cnt, 'pin', pin, ft(mod), host, '|', path)
            o += 130 + pl*2 + (4 if ver >= 3 else 0)
    for k,v in st.items():
        if k != 'DestList': print('  stream', k, len(v))
main()
