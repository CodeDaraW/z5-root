#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""拆解包含 ROOTING_ALLOWED 的 TA 记录，试探头部 4 个 u32 是否为校验值。"""
import binascii, hashlib, os, struct, zlib

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
d = open(os.path.join(REPO, 'artifacts', 'ta', 'TA.img'), 'rb').read()
MAGIC = struct.pack('<I', 0x3bf8e9c1)
offs = []
i = 0
while True:
    i = d.find(MAGIC, i)
    if i < 0:
        break
    offs.append(i)
    i += 4
offs.append(len(d))

TGT = d.find(b'ROOTING_ALLOWED')
k = max(j for j in range(len(offs) - 1) if offs[j] <= TGT)
s, e = offs[k], offs[k + 1]
rec = d[s:e]
print(f'ROOTING_ALLOWED @ {TGT:#08x}')
print(f'所属记录 #{k}: {s:#08x} - {e:#08x}  长 {len(rec)}B')
print()
hdr = [struct.unpack_from('<I', rec, 4 * j)[0] for j in range(8)]
print('头部 u32:', [f'{x:#010x}' for x in hdr])
print()
print('记录前 48B:', rec[:48].hex(' '))
print('记录末尾 40B:', rec[-40:].hex(' '))
print()
print('--- payload 文本 ---')
import re
for m in re.finditer(rb'[ -~]{3,}', rec):
    print(f'  +{m.start():#06x}  {m.group().decode("latin1")[:90]}')
print()

# 尾部 unit id 猜测
tail_u32 = [struct.unpack_from('<I', rec, len(rec) - 4 * j)[0] for j in range(1, 4)]
print('末 3 个 u32:', [f'{x:#010x}' for x in tail_u32])

# 试各种校验算法覆盖各种跨度
print()
print('--- 校验试探（目标：命中头部任一 u32）---')
cands = {}
for name, span in [('whole', rec), ('payload_after_magic', rec[4:]),
                   ('payload_after_8', rec[8:]), ('mid', rec[8:-4]),
                   ('mid_no_unit', rec[8:-8])]:
    cands[name] = span

targets = set(hdr[1:])
found = []
for name, span in cands.items():
    tests = {
        'crc32': zlib.crc32(span) & 0xFFFFFFFF,
        'adler32': zlib.adler32(span) & 0xFFFFFFFF,
        'md5_le': int.from_bytes(hashlib.md5(span).digest()[:4], 'little'),
        'md5_be': int.from_bytes(hashlib.md5(span).digest()[:4], 'big'),
        'sha1_le': int.from_bytes(hashlib.sha1(span).digest()[:4], 'little'),
        'sum32': sum(span) & 0xFFFFFFFF,
    }
    for tname, v in tests.items():
        if v in targets:
            found.append((name, tname, hex(v)))
print('命中:', found if found else '无（头部 4 个 u32 与常见校验算法都不符）')
