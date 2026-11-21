#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫 tad 的 getsize，把「服务端不肯给」的 unit 单独列出来。只读，不碰 write。

为什么需要它：ta_scan.py 只收集「成功且长度非零」的 unit，看不到被拒的那批；
而「哪些 unit 对外不可见」本身就是一条结论，需要能自己重扫出来。

用法（先 adb forward，见 guides/device-access.md）:
    python3 analysis/ta/ta_reject_scan.py                 # 默认三段区间
    python3 analysis/ta/ta_reject_scan.py 0x0000 0x1500   # 自定义区间，可给多组

输出：每个被拒 unit 一行 `<uid>  <状态名>`，末尾给汇总。

⚠️ 结果只对本机成立（不同机型/固件不同），不要提交到仓库。
⚠️ 状态 4 = `Unit not found` 是**权限过滤**，不能推出「这个 unit 不存在」。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tadif import Tad, ST  # noqa: E402

DEFAULT_RANGES = [(0x0000, 0x1500), (0x2700, 0x2800), (0x10400, 0x10500)]


def parse_ranges(argv):
    if not argv:
        return DEFAULT_RANGES
    nums = [int(a, 0) for a in argv]
    if len(nums) % 2:
        sys.exit("区间要给成对的两个数：lo hi [lo hi ...]")
    return [(nums[i], nums[i + 1]) for i in range(0, len(nums), 2)]


def main():
    t = Tad()
    if t.open(1) != 0:
        sys.exit("tad open 失败；先 adb forward tcp:19999 localfilesystem:/dev/socket/tad")

    total = ok = 0
    rejected = []
    for lo, hi in parse_ranges(sys.argv[1:]):
        print(f"--- [{lo:#06x}, {hi:#06x}) ---")
        for uid in range(lo, hi):
            st, sz = t.getsize(uid)
            total += 1
            if st == 0 and sz:
                ok += 1
            else:
                rejected.append((uid, st))
                print(f"{uid:#06x}  {ST.get(st, st)}")

    t.close()
    print()
    print(f"扫描 {total} 个 uid：可读 {ok}，被拒/不可见 {len(rejected)}")
    if rejected:
        by_status = {}
        for _, st in rejected:
            by_status[st] = by_status.get(st, 0) + 1
        for st, n in sorted(by_status.items()):
            print(f"  状态 {st} ({ST.get(st, '?')}): {n}")


if __name__ == "__main__":
    main()
