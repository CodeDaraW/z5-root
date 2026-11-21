#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""穷举 /verity_key 中所有 256B 窗口作为模数，反向定位签名验证的构造。"""
import hashlib, os, struct

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VF = os.path.join(REPO, 'artifacts', 'verity', 'vf')

key  = open(os.path.join(VF, 'verity_key.raw'), 'rb').read()
blk  = open(os.path.join(VF, 'meta8.bin'), 'rb').read()[:4096]

TLEN  = struct.unpack_from('<I', blk, 0x108)[0]
TABLE = blk[0x10c:0x10c + TLEN]
SIGS  = {'sig@0x08': blk[0x08:0x108],
         'sig@0x08_rev': blk[0x08:0x108][::-1]}

MSGS = {
    'table': TABLE,
    'table+NUL': TABLE + b'\x00',
    'hdr+table': blk[0:0x108] + TABLE,
    'blk_minus_sig': blk[0:8] + blk[0x108:],
}
DIGESTS = {}
for name, m in MSGS.items():
    DIGESTS[name + '/sha256'] = hashlib.sha256(m).digest()
    DIGESTS[name + '/sha1']   = hashlib.sha1(m).digest()

PREF = {32: bytes.fromhex('3031300d060960864801650304020105000420'),
        20: bytes.fromhex('3021300906052b0e03021a05000414')}

def pkcs1(d):
    return PREF[len(d)] + d

def parse(res, payload):
    if res[:2] != b'\x00\x01':
        return None
    i = 2
    while i < len(res) and res[i] == 0xFF:
        i += 1
    if res[i] != 0:
        return None
    return res[i+1:]

best = []
for off in range(0, len(key) - 256 + 1):
    N = int.from_bytes(key[off:off+256], 'big')
    if N.bit_length() < 1024:
        continue
    for sname, sig in SIGS.items():
        for e in (65537, 3):
            res = pow(int.from_bytes(sig, 'big'), e, N).to_bytes(256, 'big')
            if res[0] == 0 and res[1] == 1:
                tail = parse(res, b'')
                best.append((off, sname, e, res[:8].hex(), tail[:24].hex() if tail else None))

print('找到 PKCS#1 v1.5 结构的组合:', len(best))
for b in best[:10]:
    print('  模数偏移', hex(b[0]), b[1], 'e=', b[2], '头', b[3], '载荷前缀', b[4])

# 对命中的模数，再比对所有消息摘要
print()
print('--- 载荷比对 ---')
for off, sname, e, _, _ in best[:4]:
    N = int.from_bytes(key[off:off+256], 'big')
    res = pow(int.from_bytes(SIGS[sname], 'big'), e, N).to_bytes(256, 'big')
    pay = parse(res, b'')
    for dname, d in DIGESTS.items():
        if pay and pay.endswith(pkcs1(d)):
            print(f'  MATCH  模数@{hex(off)} {sname} e={e}  ->  {dname}')
        elif pay and pay.endswith(d):
            print(f'  MATCH* 模数@{hex(off)} {sname} e={e}  ->  {dname} (无 DigestInfo)')

print()
print('元数据块 0x00..0x10c 头:', blk[:8].hex(' '))
print('表长字段', TLEN, ' 表 sha256', hashlib.sha256(TABLE).hexdigest()[:32])
