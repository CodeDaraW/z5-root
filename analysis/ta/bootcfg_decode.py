#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解码 Sony S1 bootconfig（1ACE 容器）。

格式依据 aboot 中的 `s1boot_config_parser.c` 反汇编还原：

  容器:  [u16 BE? no: LE] 见下
    0x00  u16  0xCE1A      魔数（小端读出为 0xCE1A，即字节 1A CE）
    0x02  起  顶层条目流

  条目:  [u16 LE size][u8 type][u8 subtype][size-2 字节 payload]
        size 从 type 字节起算，故整条目长度 = 2 + size

  顶层 type=1 → payload = [u8 count][count 个触发器条目]
       触发器 subtype: 1=Keypad(需 size=4) 2/3/6=GPIO(5) 4=USB OTG(3) 5=PowerKey(2)
  顶层 type=2 → payload = N 组 [u32 unit][u32 值]，每组 8 字节，
       随后对 unit 递归调用 read_ta_unit 继续解析
"""

import struct
import sys

TRIG = {1: ("Keypad", 4), 2: ("GPIO", 5), 3: ("GPIO", 5),
        4: ("USB-OTG", 3), 5: ("PowerKey", 2), 6: ("GPIO", 5)}


def walk(buf, start, end, depth=0, tag=""):
    """遍历从 start 到 end 的条目流。返回消耗到的偏移。"""
    p = start
    n = 0
    while p + 4 <= end:
        size = struct.unpack_from("<H", buf, p)[0]
        if size == 0:
            break
        etype = buf[p + 2]
        esub = buf[p + 3]
        rec_end = p + 2 + size
        if rec_end > end:
            print("  " * depth + "!! 条目越界 p=%#x size=%d end=%#x" % (p, size, end))
            return p
        payload = buf[p + 4:rec_end]
        ind = "  " * depth
        print("%s[%03x] %s t=%d s=%d size=%d payload(%d)=%s" %
              (ind, p, tag, etype, esub, size, len(payload), payload[:24].hex(" ")))
        if len(payload) <= 32 and len(payload) > 0:
            a = "".join(chr(c) if 32 <= c < 127 else "." for c in payload)
            print("%s        ascii: %s" % (ind, a))
        n += 1
        p = rec_end
        if n > 200:
            print(ind + "... 截断")
            break
    return p


def decode(d):
    print("总长 %d, 头: %s" % (len(d), d[:4].hex(" ")))
    if d[:2] != b"\x1a\xce":
        print("魔数不匹配")
        return
    hl = struct.unpack_from("<H", d, 2)[0]
    print("头 u16 = %d (%#x)" % (hl, hl))
    print()
    print("=== 顶层条目流（自 offset 2）===")
    end = walk(d, 2, len(d))
    print("\n消耗到 %#x，剩余 %d 字节: %s" % (end, len(d) - end, d[end:].hex(" ")))
    print()

    # 单独展开 type=1 的触发器列表与 type=2 的 unit 引用表
    p = 2
    while p + 4 <= len(d):
        size = struct.unpack_from("<H", d, p)[0]
        if size == 0:
            break
        etype, esub = d[p + 2], d[p + 3]
        rec_end = p + 2 + size
        if rec_end > len(d):
            break
        pl = d[p + 4:rec_end]
        if etype == 1 and pl:
            cnt = pl[0]
            print("=== type1 触发器列表: count=%d ===" % cnt)
            walk(pl, 1, len(pl), depth=1, tag="trig")
            print()
        if etype == 2:
            print("=== type2 unit 引用表: %d 字节 ===" % len(pl))
            for k in range(0, len(pl) - 7, 8):
                u, v = struct.unpack_from("<II", pl, k)
                print("   +%02x  unit=%#06x  value=%#010x (%d)" % (k, u, v, v))
            print()
        p = rec_end


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "bootcfg.bin"
    decode(open(path, "rb").read())
