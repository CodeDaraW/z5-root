#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 s1sbl / aboot 中回溯 ROOTING_ALLOWED 字符串的引用点（字面量池 + PC 相对 LDR）。"""
import os
import struct

# 镜像来自设备 bootloader 分区，不入库；重建方式见 docs/guides/reproduce.md
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOOTLOADER = os.path.join(REPO, 'artifacts', 'bootloader')

def load_elf(path):
    d = open(path, 'rb').read()
    e_entry, e_phoff = struct.unpack_from('<II', d, 0x18)
    e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x2a)
    segs = []
    for k in range(e_phnum):
        o = e_phoff + k * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from('<IIIII', d, o)
        if p_type == 1:
            segs.append((p_offset, p_vaddr, p_filesz))
    return d, segs

def f2v(segs, off):
    for o, v, sz in segs:
        if o <= off < o + sz:
            return v + (off - o)
    return None

def v2f(segs, vma):
    for o, v, sz in segs:
        if v <= vma < v + sz:
            return o + (vma - v)
    return None

for name in ('s1sbl.img', 'aboot.img'):
    path = os.path.join(BOOTLOADER, name)
    d, segs = load_elf(path)
    print('=' * 72)
    print(name, ' segs:', [(hex(o), hex(v), hex(s)) for o, v, s in segs])
    so = d.find(b'ROOTING_ALLOWED')
    vma = f2v(segs, so)
    print(f'字符串文件偏移 {so:#x} -> VMA {vma:#x}')
    if vma is None:
        print('  不在任何 PT_LOAD 内，跳过')
        continue

    # 1) 字面量池：直接出现该 VMA 的 4 字节
    pool = [i for i in range(0, len(d) - 4, 4)
            if struct.unpack_from('<I', d, i)[0] == vma]
    print('字面量池命中:', [hex(p) for p in pool[:8]], f'共 {len(pool)}')

    # 2) 对每个池项，找指向它的 PC 相对 LDR
    refs = []
    for p in pool:
        pv = f2v(segs, p)
        if pv is None:
            continue
        for i in range(0, len(d) - 4, 4):
            w = struct.unpack_from('<I', d, i)[0]
            if (w & 0xFFFFF000) == 0xE59F0000:      # ARM: ldr rX, [pc, #imm]
                iv = f2v(segs, i)
                if iv is None:
                    continue
                if iv + 8 + (w & 0xFFF) == pv:
                    refs.append((iv, 'ldr', pv))
    print('ARM LDR 引用点:', [hex(r[0]) for r in refs[:10]], f'共 {len(refs)}')

    # 3) Thumb 窄/宽 LDR
    trefs = []
    for i in range(0, len(d) - 4, 2):
        h = struct.unpack_from('<H', d, i)[0]
        iv = f2v(segs, i)
        if iv is None:
            continue
        if (h & 0xF800) == 0x4800:
            tgt = ((iv + 4) & ~3) + (h & 0xFF) * 4
            for p in pool:
                if f2v(segs, p) == tgt:
                    trefs.append((iv, 'ldr.n', tgt))
        elif h == 0xF8DF:
            h2 = struct.unpack_from('<H', d, i + 2)[0]
            tgt = ((iv + 4) & ~3) + (h2 & 0xFFF)
            for p in pool:
                if f2v(segs, p) == tgt:
                    trefs.append((iv, 'ldr.w', tgt))
    print('Thumb LDR 引用点:', [hex(t[0]) for t in trefs[:10]], f'共 {len(trefs)}')
