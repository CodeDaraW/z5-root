#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 TA uid 空间：找出"设备上有、但 dump 里没有"的可读 unit。

只读（getsize）。若某个 getsize 返回 0 而 dump 里没有对应 uid，
说明 ta_parse2 漏了记录；若两者完全一致，则解析器的完整性得到外部确认。
"""
import os
import sys

from ta_parse2 import records
from tadif import Tad

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DUMP = os.path.join(REPO, "artifacts", "ta", "TA.img")

RANGES = [(0x0000, 0x1500), (0x2700, 0x2800), (0x10400, 0x10500)]


def main():
    d = open(DUMP, "rb").read()
    rs = records(d)
    have = set(r["uid"] for r in rs)
    print("dump 内 uid: %d 个" % len(have))

    t = Tad()
    t.open(1)
    found = 0
    extra = []
    denied = 0
    for lo, hi in RANGES:
        for u in range(lo, hi):
            st, sz = t.getsize(u)
            if st == 0:
                found += 1
                if u not in have:
                    extra.append((u, sz))
            elif st == 4:
                denied += 1
            else:
                print("  %.5x st=%d" % (u, st))
    t.close()

    print("范围内可读 unit : %d" % found)
    print("范围内拒绝/不存在: %d" % denied)
    print("dump 未收录的可读 unit: %d" % len(extra))
    for u, sz in extra[:60]:
        print("   %.5x size=%d" % (u, sz))

    # 反向：dump 里有、扫描范围内却读不到的（应全部落在安全区）
    rlo, rhi = 0, 0x1500
    miss = [u for u in sorted(have) if rlo <= u < rhi]
    print("\ndump 在 0x0000-0x1500 内共 %d 个 uid" % len(miss))


if __name__ == "__main__":
    main()
