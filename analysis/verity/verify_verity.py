#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verity 全链闭环复核：表 -> root -> 顶块 -> L1 -> L0 -> 数据块，逐级重算。"""
import hashlib, os, re, struct

# 仓库根 = 本文件上溯三级；verity 探针产物固定在 artifacts/verity/
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
B = os.path.join(REPO, 'artifacts', 'verity')
def rd(p):
    return open(os.path.join(B, p), 'rb').read()

dmend = rd('sys_dmend.bin')
tail2m = rd('sys_tail2m.bin')
tail1m = rd('p44_tail1m.bin')
top   = rd('vf/top.bin')
l1_0  = rd('vf/l1_0.bin')
l0_0  = rd('vf/l0_0.bin')
l0_1  = rd('vf/l0_1.bin')
d5    = rd('vf/d5.bin')

PART_SIZE = 5513412608
PART_BLKS = PART_SIZE // 4096
BS = 4096
ZERO = b'\x00' * BS

# ---- 表解析（dm-verity 标准 10 字段）----
i = dmend.find(b'\x01\xb0\x01\xb0')
txt = dmend[i:i+1024].decode('latin1', 'replace')
line = [l for l in re.split(r'[\x00\n]', txt) if l.startswith('1 ')]
print('=' * 70)
print('[表] 原始行（截断）:')
print('  ' + (line[0][:150] if line else 'PARSE FAIL'))
toks = line[0].split()
ver, ddev, hdev = toks[0], toks[1], toks[2]
dbs, hbs = int(toks[3]), int(toks[4])
num_data_blocks, hash_start_block = int(toks[5]), int(toks[6])
alg, root, salt = toks[7], bytes.fromhex(toks[8]), bytes.fromhex(toks[9])
print(f'  字段: ver={ver} dbs={dbs} hbs={hbs} num_data_blocks={num_data_blocks} '
      f'hash_start_block={hash_start_block} alg={alg}')
print(f'  root={root.hex()[:32]}…  salt={salt.hex()[:32]}… (salt {len(salt)}B)')

# ---- 账目 ----
L0_entries = num_data_blocks
L0_blocks = -(-L0_entries // 128)
L1_blocks = -(-L0_blocks // 128)
tree_blocks = 1 + L1_blocks + L0_blocks
meta_blocks = 8
print()
print('[账目]')
print(f'  dm-0 应映射 {num_data_blocks*BS} B   (实测 dm-0 size = 5469962240)')
print(f'  L0 条目 {L0_entries} -> L0 块 {L0_blocks} -> L1 块 {L1_blocks} -> 顶层 1')
print(f'  树总块数 {tree_blocks} = {tree_blocks*BS} B')
print(f'  数据+元数据+树 = {num_data_blocks+meta_blocks+tree_blocks} 块, '
      f'分区 {PART_BLKS} 块 -> 尾部填充 {PART_BLKS-(num_data_blocks+meta_blocks+tree_blocks)} 块 '
      f'= {(PART_BLKS-(num_data_blocks+meta_blocks+tree_blocks))*BS} B')

# ---- 证据 A ----
V = hashlib.sha256(salt + ZERO).digest()
v_end = len(tail1m.rstrip(b'\x00'))
tailV = tail1m[v_end-32:v_end]
print()
print('[A] sha256(salt||4096 零块) vs 尾部重复值')
print(f'  计算 {V.hex()[:40]}…')
print(f'  尾部 {tailV.hex()[:40]}…')
print('  结果:', 'MATCH' if V == tailV else 'MISMATCH')

# ---- 证据 B ----
h = hashlib.sha256(salt + top).digest()
print()
print('[B] sha256(salt||顶层块) vs 表里 root')
print(f'  计算 {h.hex()[:40]}…')
print(f'  root {root.hex()[:40]}…   -> {"MATCH" if h == root else "MISMATCH"}')

# ---- 证据 C: 顶层条目 = L1 块哈希 ----
nz_top = sum(1 for k in range(0, BS, 32) if top[k:k+32] != ZERO[:32])
ent0 = top[0:32]
calc_l1 = hashlib.sha256(salt + l1_0).digest()
print()
print('[C] 顶层条目0 vs sha256(salt||L1块0)')
print(f'  顶层次块0 非零条目数 = {nz_top}   (L1 理论值 {L1_blocks})')
print(f'  顶层[0]   {ent0.hex()[:40]}…')
print(f'  实算      {calc_l1.hex()[:40]}…   -> {"MATCH" if ent0 == calc_l1 else "MISMATCH"}')

# ---- 证据 D: L1 条目 = L0 块哈希 ----
calc_l0_0 = hashlib.sha256(salt + l0_0).digest()
print()
print('[D] L1块0 条目0 vs sha256(salt||L0块0)')
print(f'  L1[0] {l1_0[0:32].hex()[:40]}…')
print(f'  实算  {calc_l0_0.hex()[:40]}…   -> {"MATCH" if l1_0[0:32] == calc_l0_0 else "MISMATCH"}')
calc_l0_1 = hashlib.sha256(salt + l0_1).digest()
print(f'  L1[1] vs sha256(salt||L0块1) -> {"MATCH" if l1_0[32:64] == calc_l0_1 else "MISMATCH"}')

# ---- 证据 E: L0 条目 = 数据块哈希 ----
calc_d5 = hashlib.sha256(salt + d5).digest()
print()
print('[E] L0块0 条目5 vs sha256(salt||数据块5)')
print(f'  L0[5] {l0_0[5*32:6*32].hex()[:40]}…')
print(f'  实算  {calc_d5.hex()[:40]}…   -> {"MATCH" if l0_0[5*32:6*32] == calc_d5 else "MISMATCH"}')

# ---- 证据 F: 尾部普查与异词定位 ----
print()
print('[F] tail2m 词普查')
from collections import Counter
c = Counter(tail2m[k:k+32] for k in range(0, len(tail2m) - 31, 32))
print(f'  词数 {len(tail2m)//32}  不同值 {len(c)}')
for w, n in c.most_common(3):
    tag = 'V' if w == V else ('零' if w == ZERO[:32] else '其他')
    print(f'   x{n:<6} [{tag}] {w.hex()[:40]}…')
oddw = [w for w, n in c.items() if w not in (ZERO[:32], V)][0]
off = tail2m.find(oddw)
# 该词在分区中的绝对位置：tail2m = 分区最后 2MB
abs_off = PART_SIZE - len(tail2m) + off
tree_start = hash_start_block * BS
l0_start = tree_start + (1 + L1_blocks) * BS
ent_idx = (abs_off - l0_start) // 32
print(f'  异词 @ 窗口 {hex(off)} -> 分区绝对 {hex(abs_off)}')
print(f'  归属: L0 条目 #{ent_idx}  (= 数据块 #{ent_idx})')
print(f'  其后零条目数 = {L0_entries - 1 - ent_idx}')

# ---- 汇总：六次比较，任一处不匹配即非零退出 ----
# 数「MATCH 有几个」会把「5 个对、1 个错」看成通过，所以判据是退出码。
checks = [
    ('A', V == tailV),
    ('B', h == root),
    ('C', ent0 == calc_l1),
    ('D1', l1_0[0:32] == calc_l0_0),
    ('D2', l1_0[32:64] == calc_l0_1),
    ('E', l0_0[5 * 32:6 * 32] == calc_d5),
]
bad = [n for n, ok in checks if not ok]
print()
print(f'[汇总] {len(checks)} 次比较：'
      + ('全部 MATCH' if not bad else '失败 ' + ', '.join(bad)))
raise SystemExit(1 if bad else 0)
