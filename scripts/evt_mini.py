#!/usr/bin/env python3
"""Recupera registros de log .evt (Windows XP/2003) por assinatura LfLe em dumps de memoria.
Uso: python3 -I evt_mini.py DUMP [filtro_de_origem]
Saida: data/hora (UTC) | numero do registro | origem (source) de cada registro encontrado.
"""
import re, struct, sys, datetime
d = open(sys.argv[1], 'rb').read()
for m in re.finditer(b'LfLe', d):
    p = m.start() - 4
    tam, _, num, ger = struct.unpack_from('<I4sII', d, p)
    if not (56 <= tam <= 65536 and 1e9 < ger < 1.9e9): continue
    txt = d[p+56:p+tam-4].decode('utf-16-le', 'ignore').split('\x00')
    if len(sys.argv) > 2 and sys.argv[2].lower() not in txt[0].lower(): continue
    print(datetime.datetime.fromtimestamp(ger, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), 'UTC | registro', num, '|', txt[0])
