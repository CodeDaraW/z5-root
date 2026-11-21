#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打印 (src, tgt, class) 在 avtab 里的全部直接 allow 权限位.

用法:
  python3 analysis/selinux/polq.py init init_tmpfs file
  python3 analysis/selinux/polq.py init tmpfs dir

注意: 只展开 avtab 直接条目, 不做 type attribute 展开 (domain / file_type 等)。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# 仓库根 = 本文件上溯三级；策略本体在 artifacts/ 下（不入库）
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
DUMP = os.path.join(REPO, 'artifacts', 'device', 'partitions')

import sepolicy_parse as S

AVTAB_ALLOWED = 0x0001


def main():
    if len(sys.argv) < 4:
        sys.stderr.write('usage: polq.py <src> <tgt> <class>\n')
        return 2
    src, tgt, cls = sys.argv[1:4]
    sep = os.path.join(DUMP, 'sepolicy')
    p = S.Policy().load(sep)

    ok = True
    for nm in (src, tgt):
        if p.types.get(nm) is None:
            print('!! type %s ABSENT from policy' % nm)
            ok = False
    if p.classes.get(cls) is None:
        print('!! class %s ABSENT' % cls)
        return 1
    if not ok:
        return 1

    sv = p.types[src]
    tv = p.types[tgt]
    cv = p.classes[cls]
    pm = p.perms[cv]
    bit2name = {}
    for k, v in pm.items():
        bit2name[v] = k

    mask = 0
    for (asrc, atgt, acls, spec, datum) in p.avtab:
        if acls == cv and (spec & AVTAB_ALLOWED) and asrc == sv and atgt == tv:
            mask |= datum

    names = [bit2name[b] for b in sorted(bit2name) if mask & (1 << b)]
    print('%-14s -> %-14s : %-10s = %s'
          % (src, tgt, cls, ','.join(names) if names else '<NONE DIRECT>'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
