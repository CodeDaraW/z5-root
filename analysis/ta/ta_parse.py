#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TA 分区记录解析器 **v1（已作废，仅存档）**。

⚠️ 这里的记录格式 `[magic][marker 0x34ffffff][payload][unit_id][X]` 是错的：
把首尾读反、整体错位一条。正确布局是 `[uid][size][magic][flags][data][pad]`，
见 `ta_parse2.py`（2082 条全盘自洽，且经 tad 权威尺寸逐字节校验）。
对应勘误见 `../../docs/research/bl-exploration.md` §14.1 与 `../../docs/pitfalls.md`。

保留此文件只为留下"当初怎么理解错的"这一份证据，不要用它解析 TA。
"""
import struct, sys

MAGIC = 0x3bf8e9c1
MARK = 0x34ffffff


def records(d):
    m = struct.pack('<I', MAGIC)
    offs = []
    i = 0
    while True:
        i = d.find(m, i)
        if i < 0:
            break
        offs.append(i)
        i += 4
    out = []
    for k, s in enumerate(offs):
        e = offs[k + 1] if k + 1 < len(offs) else None
        if e is None:
            break
        rec = d[s:e]
        if len(rec) < 20 or (len(rec) % 4):
            continue
        mark, uid, x = struct.unpack_from('<III', rec, 4), None, None
        mark = struct.unpack_from('<I', rec, 4)[0]
        uid = struct.unpack_from('<I', rec, len(rec) - 8)[0]
        x = struct.unpack_from('<I', rec, len(rec) - 4)[0]
        payload = rec[8:len(rec) - 8]
        out.append(dict(idx=len(out), off=s, size=len(rec), mark=mark,
                        uid=uid, x=x, payload=payload))
    return out


if __name__ == '__main__':
    import os
    REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, 'artifacts', 'ta', 'TA.img')
    d = open(path, 'rb').read()
    rs = records(d)
    print('records:', len(rs))
    print('marker values:', sorted({hex(r['mark']) for r in rs}))
    print('uid monotonic:', all(a['uid'] < b['uid'] for a, b in zip(rs, rs[1:])))
    print()
    print(f'{"idx":>4} {"off":>8} {"size":>5} {"uid":>7} {"x":>6}  payload head')
    for r in rs[:12]:
        t = ''.join(chr(c) if 32 <= c < 127 else '.' for c in r['payload'][:24])
        print(f"{r['idx']:4} {r['off']:#08x} {r['size']:5} {r['uid']:#7x} {r['x']:6}  {t}")
    # 文本型 payload 统计
    txt = [r for r in rs if r['payload'] and sum(32 <= c < 127 or c in (0, 10, 13) for c in r['payload']) / len(r['payload']) > 0.85]
    print()
    print('text-like payload records:', len(txt))
    big = sorted(rs, key=lambda r: -len(r['payload']))[:8]
    print('largest payloads:', [(r['uid'], len(r['payload'])) for r in big])
