#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELF32-ARM 反汇编辅助：按 VA 反汇编、解析字面量池、标注字符串与调用目标。"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN


class Img:
    def __init__(self, path):
        self.path = path
        self.d = open(path, 'rb').read()
        self.segs = []
        if self.d[:4] == b'\x7fELF':
            e_phoff = struct.unpack_from('<I', self.d, 0x1c)[0]
            n = struct.unpack_from('<H', self.d, 0x2c)[0]
            for k in range(n):
                o = e_phoff + k * 32
                t, off, va, pa, fs = struct.unpack_from('<IIIII', self.d, o)
                if t == 1:
                    self.segs.append((off, va, fs))
        else:  # 裸二进制：假定 base 到文件末尾
            self.segs = [(0, 0, len(self.d))]

    def f2v(self, o):
        for off, va, fs in self.segs:
            if off <= o < off + fs:
                return va + o - off
        return None

    def v2f(self, v):
        for off, va, fs in self.segs:
            if va <= v < va + fs:
                return off + v - va
        return None

    def u32(self, v):
        f = self.v2f(v)
        if f is None or f + 4 > len(self.d):
            return None
        return struct.unpack_from('<I', self.d, f)[0]

    def cstr(self, v, maxlen=80):
        f = self.v2f(v)
        if f is None:
            return None
        e = self.d.find(b'\x00', f, f + maxlen)
        if e < 0 or e == f:
            return None
        s = self.d[f:e]
        if all(32 <= c < 127 or c in (9, 10, 13) for c in s):
            return s.decode('latin1')
        return None


def dis(img, start, end, thumb=False, annotate=True, show_bytes=False):
    f = img.v2f(start)
    if f is None:
        print('  <bad va %#x>' % start)
        return
    code = img.d[f:f + (end - start)]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    md.detail = False
    md.skipdata = True
    out = []
    for ins in md.disasm(code, start):
        line = '%08x  ' % ins.address
        if show_bytes:
            line += (ins.bytes.hex() + ' ' * 12)[:11] + ' '
        line += '%-8s %s' % (ins.mnemonic, ins.op_str)
        note = ''
        if annotate:
            m = ins.mnemonic
            ops = ins.op_str
            if m in ('bl', 'blx') and ops.startswith('#'):
                tgt = int(ops[1:], 0)
                s = img.cstr(tgt)
                if s:
                    note = '  ; "%s"' % s[:60]
                else:
                    note = '  ; -> %#x' % tgt
            elif m == 'ldr' and '[pc' in ops:
                # ldr rX, [pc, #imm]
                try:
                    imm = int(ops.split('#')[-1].rstrip(']'), 0)
                    pcv = (ins.address + 8) & ~3
                    pv = pcv + imm
                    val = img.u32(pv)
                    if val is not None:
                        s = img.cstr(val)
                        note = '  ; [%#x]=%#x' % (pv, val)
                        if s:
                            note += ' "%s"' % s[:60]
                except Exception:
                    pass
            elif m == 'add' and 'pc' in ops:
                try:
                    imm = int(ops.split('#')[-1], 0)
                    pv = ins.address + 8 + imm
                    s = img.cstr(pv)
                    if s:
                        note = '  ; "%s"' % s[:60]
                    else:
                        note = '  ; -> %#x' % pv
                except Exception:
                    pass
            elif m in ('movw', 'mov') and ops.startswith('r') and '#' in ops:
                pass
        out.append(line + note)
    print('\n'.join(out))


if __name__ == '__main__':
    path = sys.argv[1]
    start = int(sys.argv[2], 0)
    end = int(sys.argv[3], 0)
    thumb = len(sys.argv) > 4 and sys.argv[4] == 'thumb'
    img = Img(path)
    print('# %s segs=%s' % (path, [(hex(a), hex(b), hex(c)) for a, b, c in img.segs]))
    dis(img, start, end, thumb=thumb, show_bytes=True)
