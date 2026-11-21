#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 ARM 镜像里找"字面量池被谁 ldr 引用"：xref_lit.py <img> <target_va>"""
import struct, sys
from arm_dis import Img

def xrefs(img, target):
    out = []
    d = img.d
    for off, va, fs in img.segs:
        # 池里出现该地址的位置
        for o in range(off, off + fs - 4, 4):
            if struct.unpack_from('<I', d, o)[0] != target:
                continue
            pva = va + o - off
            # 向前 4KB 找 ldr rX,[pc,#imm]
            for q in range(o - 4096, o, 4):
                if q < off:
                    continue
                w = struct.unpack_from('<I', d, q)[0]
                if (w & 0x0F7F0000) != 0x051F0000:
                    continue
                imm = w & 0xFFF
                qva = va + q - off
                if (qva + 8 + imm) & ~3 == pva:
                    out.append((qva, qva + 8 + imm))
    return out

if __name__ == '__main__':
    img = Img(sys.argv[1])
    t = int(sys.argv[2], 0)
    for ins, pool in xrefs(img, t):
        print('  ldr @ %08x  pool %08x' % (ins, pool))
