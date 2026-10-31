#!/usr/bin/env python3
"""Validate the K100 Pro Max memory map and the FD/toml agreement before building."""
import re
MAP = 'Mu-Silicium/Platforms/OnePlus/songyuanPkg/Library/MemoryMapLib/MemoryMapLib.c'
TOM = 'Mu-Silicium/Resources/Configs/songyuan.toml'
s = open(MAP, encoding='utf-8', errors='replace').read()
rows = []
for ln in s.split('\n'):
    m = re.match(r'\s*\{"([^"]+)"\s*,\s*(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)', ln)
    if m:
        rows.append((m.group(1).strip(), int(m.group(2), 16), int(m.group(3), 16)))
assert len(rows) >= 60, ('too few entries', len(rows))
d = {n: (a, l) for n, a, l in rows}
need = {
    'XNU_Payload': (0xF0000000, 0x03800000),
    'UEFI_FD': (0xC6900000, 0x300000),
    'FD_Reserved': (0xC6800000, 0x100000),
    'UEFI_FD_Reserved': (0xC6C00000, 0x200000),
    'CPU_Vectors': (0xC6E00000, 0x1000),
    'Kernel': (0xC7800000, 0x10000000),
    'DXE_Heap': (0xB00F0000, 0x131A0000),
    'SPLASH_REGION': (0xFC800000, 0x02B00000),
    'TRUST_UI_VM_REGION': (0xF3800000, 0x05000000),
}
for n, v in need.items():
    assert n in d, 'missing entry ' + n
    assert d[n] == v, (n, hex(d[n][0]), hex(d[n][1]), hex(v[0]), hex(v[1]))
bad = [n for n, a, l in rows if a in (0xA7000000, 0xA7100000, 0xA7400000, 0xA8000000, 0xB8000000)]
assert not bad, ('stale package addresses', bad)
ddr = sorted([(a, l, n) for n, a, l in rows if 0x80000000 <= a < 0x100000000], key=lambda x: x[0])
for (a1, l1, n1), (a2, l2, n2) in zip(ddr, ddr[1:]):
    assert a1 + l1 <= a2, ('overlap', n1, n2, hex(a1), hex(l1), hex(a2))
t = open(TOM, encoding='utf-8').read()
m = re.search(r'\[uefi_fd\][^\[]*?base\s*=\s*(0x[0-9A-Fa-f]+)', t)
assert m and int(m.group(1), 16) == 0xC6900000, ('toml FD base', m.group(1) if m else None)
print('memory map OK: %d entries, FD 0xC6900000, XNU payload 0xF0000000+0x3800000' % len(rows))