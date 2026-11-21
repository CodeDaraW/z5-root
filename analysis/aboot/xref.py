#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 ARM 镜像中查找字符串/常量的代码引用（字面量池 + PC 相对加载）。"""
import struct, sys
from arm_dis import Img


def find_pool_refs(img, value):
    """返回引用该 32 位值的 ldr 指令地址列表。"""
    hits = []
    for off, va, fs in img.segs:
        seg = img.d[off:off + fs]
        pv = None
        idx = 0
        pv_list = []
        while True:
            idx = seg.find(struct.pack('<I', value), idx)
            if idx < 0:
                break
            pv_list.append(va + idx)
            idx += 1
        for instr_off in range(0, len(seg) - 4, 4):
            w = struct.unpack_from('<I', seg, instr_off)[0]
            if (w & 0xFFFF0000) == 0xE59F0000:      # ldr rX, [pc, #imm]
                addr = va + instr_off
                target = addr + 8 + (w & 0xFFF)
                if target in pv_list:
                    hits.append((addr, (w >> 12) & 0xF, 'ldr'))
            elif (w & 0xFFFF0000) == 0xE28F0000:    # add rX, pc, #imm
                addr = va + instr_off
                target = addr + 8 + (w & 0xFFF)
                if target in pv_list:
                    hits.append((addr, (w >> 12) & 0xF, 'adr'))
    return hits


if __name__ == '__main__':
    img = Img(sys.argv[1])
    what = sys.argv[2]
    if what.startswith('0x'):
        val = int(what, 16)
        print('constant %#x refs:' % val, [(hex(a), r, k) for a, r, k in find_pool_refs(img, val)])
    else:
        s = what.encode()
        f = img.d.find(s)
        if f < 0:
            print('string not found')
            sys.exit(0)
        va = img.f2v(f)
        print('"%s" @ file %#x  va %#x' % (what, f, va))
        for a, r, k in find_pool_refs(img, va):
            print('  ref @ %#x  (%s r%d)' % (a, k, r))
