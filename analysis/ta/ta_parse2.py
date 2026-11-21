#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TA(TrimArea) 记录解析器 v2。

记录布局（经 uid=0x47/0x52/0x55/0xBF 与 tad 权威尺寸比对确认）：

    [u32 uid][u32 size][u32 magic=0x3BF8E9C1][u32 flags]
    [size 字节数据][0~3 字节填充]

其中填充字节 = 重复 flags 的**低字节**（常见 0xFF / 0x15 / 0x23 / 0x13），
因此"填充"看起来像是把 flags 复制了一份，这也是早期把它误读成
"payload 尾部字段"的原因。

实测：1211 条需填充记录中 1200 条符合上述规则（99.09%）；11 条例外全部位于
0x60000 之后的后写区（含 0x7DA、0x84F），例外只影响"填充值取什么"，
不影响 size 字段（这 11 条的 data_off+size+pad 仍精确等于下一条起点）。
"""

import struct
import sys

MAGIC = 0x3BF8E9C1


def records(d):
    """返回记录列表。每项: idx/uid/size/off/mark/data/data_off"""
    out = []
    i = 0
    n = len(d)
    idx = 0
    while True:
        i = d.find(struct.pack("<I", MAGIC), i)
        if i < 0:
            break
        # 头部在 magic 之前 8 字节
        hdr = i - 8
        if hdr < 0:
            i += 4
            continue
        uid, size = struct.unpack_from("<II", d, hdr)
        mark = struct.unpack_from("<I", d, i + 4)[0]
        data_off = i + 8
        if size > n - data_off:
            i += 4
            continue
        out.append({
            "idx": idx, "uid": uid, "size": size,
            "off": hdr, "mark": mark,
            "data_off": data_off,
            "data": d[data_off:data_off + size],
        })
        idx += 1
        # 跳到下一条记录头
        pad = (-size) % 4
        i = data_off + size + pad
    return out


if __name__ == "__main__":
    import os
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(repo, "artifacts", "ta", "TA.img")
    d = open(path, "rb").read()
    rs = records(d)
    print("size=%d  records=%d" % (len(d), len(rs)))

    # 分区统计：TA 是分段存储，整盘"单调递增"本就是伪命题，分开看才有意义
    def mono(seq):
        us = [r["uid"] for r in seq]
        return all(us[i] <= us[i + 1] for i in range(len(us) - 1))

    cfg = [r for r in rs if r["off"] < 0x40000]
    gap = [r for r in rs if 0x40000 <= r["off"] < 0x60000]
    log = [r for r in rs if r["off"] >= 0x60000]
    blocks = []
    for base in (0x00000, 0x20000):
        sub = [r for r in cfg if base <= r["off"] < base + 0x20000]
        if sub:
            blocks.append("%d 条(uid %.4x..%.4x,单调=%s)"
                          % (len(sub), min(x["uid"] for x in sub),
                             max(x["uid"] for x in sub), mono(sub)))
    print("  配置区 off<0x40000 : %4d 条，分 %d 个存储块：" % (len(cfg), len(blocks)))
    for b in blocks:
        print("      - %s" % b)
    if gap:
        print("  中间区 0x4~0x6万  : %4d 条" % len(gap))
    print("  日志区 off>=0x60000: %4d 条  uid 单调=%s  (乱序属正常：追加写)" % (len(log), mono(log)))

    from collections import Counter
    dup = [u for u, n in Counter(r["uid"] for r in rs).items() if n > 1]
    print("  重复 uid           : %4d 个" % len(dup))

    ok = bad = nofill = 0
    for r in rs:
        pad = (-r["size"]) % 4
        if pad == 0:
            nofill += 1
            continue
        end = r["data_off"] + r["size"]
        if d[end:end + pad] == bytes([r["mark"] & 0xFF]) * pad:
            ok += 1
        else:
            bad += 1
    print("  填充规则(flags低字节): %4d 符合 / %d 例外 / %d 无需填充" % (ok, bad, nofill))
    print()
    print("%4s %8s %6s %5s  %-28s %s" % ("idx", "uid", "size", "mark", "head", "ascii"))
    for r in rs[:12]:
        h = r["data"][:16].hex(" ")
        a = "".join(chr(c) if 32 <= c < 127 else "." for c in r["data"][:16])
        print("%4d %8x %6d %5x  %-28s %s" % (r["idx"], r["uid"], r["size"],
                                             r["mark"] & 0xFF, h, a))
