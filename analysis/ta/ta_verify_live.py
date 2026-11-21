#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 tad 的权威尺寸校验 TA.img dump 的解析结果。

只读：仅 open/getsize/read，不写任何 unit。
目的：补上 §4-A 第一号缺口——确认 ta_parse2 的 [uid][size][magic][flags] 布局
对**全量**记录成立，而不只是抽样的几个。
"""
import os
import struct
import sys

from ta_parse2 import records
from tadif import Tad, ST

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DUMP = os.path.join(REPO, "artifacts", "ta", "TA.img")


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    d = open(DUMP, "rb").read()
    rs = records(d)

    # uid -> [size, 次数]；同一 uid 在配置区和日志区各有一份时，
    # 设备实际返回的是**配置区**那份（日志区是历史写记录，尺寸可能不同）。
    live = {}
    for r in rs:
        e = live.setdefault(r["uid"], [0, 0])
        if e[1] == 0 or r["off"] < 0x40000:
            e[0] = r["size"]
        e[1] += 1

    uids = sorted(live)
    if limit:
        uids = uids[:limit]
    print("dump: %d 条记录, %d 个不同 uid" % (len(rs), len(live)))
    print("开始逐个询问 tad（只读）...\n")

    t = Tad()
    if t.open(1) != 0:
        print("open 失败")
        return

    same = 0
    diff = []
    denied = []
    other = []
    bytes_ok = bytes_bad = 0
    bytes_bad_list = []

    for n, u in enumerate(uids, 1):
        sz_dump = live[u][0]
        try:
            st, sz = t.getsize(u)
        except Exception as e:
            print("  %.4x getsize 异常 %s" % (u, e))
            t = Tad()
            t.open(1)
            continue
        if st == 4:
            denied.append(u)
            continue
        if st != 0:
            other.append((u, st, ST.get(st, "?")))
            continue
        if sz != sz_dump:
            diff.append((u, sz_dump, sz))
            continue
        same += 1
        # 尺寸一致才做内容比对
        try:
            st2, data = t.read(u)
        except Exception as e:
            print("  %.4x read 异常 %s" % (u, e))
            t = Tad()
            t.open(1)
            continue
        if st2 != 0:
            other.append((u, st2, "read:" + ST.get(st2, "?")))
            continue
        # dump 里取该 uid 的权威记录（优先配置区）
        cand = [r for r in rs if r["uid"] == u]
        rec = [r for r in cand if r["off"] < 0x40000][0] if any(
            r["off"] < 0x40000 for r in cand) else cand[-1]
        if data == rec["data"]:
            bytes_ok += 1
        else:
            bytes_bad += 1
            bytes_bad_list.append((u, len(rec["data"]), len(data)))
        if n % 200 == 0:
            print("  ... 已查 %d/%d" % (n, len(uids)))

    print("\n==== 汇总 ====")
    print("尺寸一致           : %d" % same)
    print("  其中内容逐字节相同: %d" % bytes_ok)
    print("  其中内容不同      : %d" % bytes_bad)
    for x in bytes_bad_list[:20]:
        print("     %.4x dump=%d live=%d" % x)
    print("尺寸不一致         : %d" % len(diff))
    for u, a, b in diff[:40]:
        print("     %.4x dump=%d tad=%d  (差 %+d)" % (u, a, b, b - a))
    print("安全区拒绝(Unit not found): %d" % len(denied))
    if denied:
        s = " ".join("%.4x" % u for u in denied)
        print("     " + s[:1200])
    print("其他错误           : %d" % len(other))
    for u, st, m in other[:20]:
        print("     %.4x st=%d %s" % (u, st, m))
    t.close()


if __name__ == "__main__":
    main()
