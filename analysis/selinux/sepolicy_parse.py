#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sepolicy 二进制策略解析器（针对 Sony 3.10 / Android 6, policyvers=30）

格式依据 kernel-exact/security/selinux/ss/policydb.c 逐函数核对：
  policydb_read() -> symtab read_f[] -> avtab_read() -> ...

第一版只解析到 avtab 结束（足够回答 type/class/perm 授权问题），
后面 ocontext/genfs/range/type_attr_map 的偏移由 --trace 打印。

用法:
  python3 sepolicy_parse.py --selftest
  python3 sepolicy_parse.py --query shell tmpfs file execute
  python3 sepolicy_parse.py --dump-types | grep shell
"""

import struct
import sys
import os

MAGIC = 0xF97CFF8C

# avtab specified 标志
AVTAB_ALLOWED       = 0x0001
AVTAB_AUDITALLOW    = 0x0002
AVTAB_AUDITDENY     = 0x0004
AVTAB_AV            = 0x0007
AVTAB_TRANSITION    = 0x0010
AVTAB_MEMBER        = 0x0020
AVTAB_CHANGE        = 0x0040
AVTAB_TYPE          = 0x0070
AVTAB_OPNUM_ALLOWED   = 0x0100
AVTAB_OPNUM_AUDITALLOW= 0x0200
AVTAB_OPNUM_DONTAUDIT = 0x0400
AVTAB_OPNUM         = 0x0700
AVTAB_OPTYPE_ALLOWED  = 0x1000
AVTAB_OPTYPE_AUDITALLOW=0x2000
AVTAB_OPTYPE_DONTAUDIT= 0x4000
AVTAB_OPTYPE        = 0x7000
AVTAB_OP            = 0x7700
AVTAB_ENABLED       = 0x8000

# CEXPR
CEXPR_NOT   = 1
CEXPR_AND   = 2
CEXPR_OR    = 3
CEXPR_ATTR  = 4
CEXPR_NAMES = 5


class R:
    def __init__(self, data, off=0):
        self.d = data
        self.o = off

    def u32(self):
        v = struct.unpack_from('<I', self.d, self.o)[0]
        self.o += 4
        return v

    def u16(self):
        v = struct.unpack_from('<H', self.d, self.o)[0]
        self.o += 2
        return v

    def u8(self):
        v = self.d[self.o]
        self.o += 1
        return v

    def u64(self):
        v = struct.unpack_from('<Q', self.d, self.o)[0]
        self.o += 8
        return v

    def raw(self, n):
        v = self.d[self.o:self.o + n]
        if len(v) != n:
            raise EOFError('need %d bytes at 0x%x, got %d' % (n, self.o, len(v)))
        self.o += n
        return v

    def name(self):
        n = self.u32()
        if n > 4096:
            raise ValueError('absurd name len %d at 0x%x' % (n, self.o - 4))
        return self.raw(n).decode('utf-8', 'replace')

    def ebitmap(self):
        mapunit = self.u32()
        highbit = self.u32()
        count = self.u32()
        if mapunit != 64:
            raise ValueError('ebitmap mapunit %d != 64 at 0x%x' % (mapunit, self.o - 12))
        if count > 100000:
            raise ValueError('ebitmap count %d absurd at 0x%x' % (count, self.o - 8))
        bits = set()
        if highbit == 0:
            return bits            # ebitmap_read: highbit==0 -> 不读任何 node
        for _ in range(count):
            startbit = self.u32()
            m = self.u64()
            b = 0
            while m:
                if m & 1:
                    bits.add(startbit + b)
                m >>= 1
                b += 1
        return bits


class Policy:
    def __init__(self):
        self.types = {}        # name -> value
        self.type_prop = {}    # value -> (primary, attribute, bounds)
        self.type_val = {}     # value -> name
        self.classes = {}      # name -> value
        self.class_val = {}    # value -> name
        self.perms = {}        # class_value -> {perm_name: bit_index}
        self.roles = {}
        self.bools = {}
        self.commons = {}      # common name -> {perm: bit}
        self.vers = 0
        self.avtab = []        # (src, tgt, cls, specified, datum)
        self.permissive_map = set()
        self.policycaps = set()
        self.isids = {}

    # ---------- 符号表 ----------
    def read_perm(self, r, table):
        # perm_read: u32 len, u32 value, bytes name
        n = r.u32()
        val = r.u32()
        nm = r.raw(n).decode('utf-8', 'replace')
        # ★ SELinux 权限 value 从 1 开始，avtab 的 datum bit 索引 = value - 1
        table[nm] = val - 1

    def read_constraints(self, r, ncons, allowxtarget, vers):
        for _ in range(ncons):
            permissions = r.u32()
            nexpr = r.u32()
            for _ in range(nexpr):
                etype = r.u32()
                attr = r.u32()
                op = r.u32()
                if etype == CEXPR_NAMES:
                    r.ebitmap()
                    if vers >= 29:          # POLICYDB_VERSION_CONSTRAINT_NAMES
                        r.ebitmap()         # types
                        r.ebitmap()         # negset
                        r.u32()             # flags

    def read_common(self, r, vers=None):
        n = r.u32()
        value = r.u32()
        nprim = r.u32()
        nel = r.u32()
        nm = r.raw(n).decode('utf-8', 'replace')
        tbl = {}
        for _ in range(nel):
            self.read_perm(r, tbl)
        self.commons[nm] = tbl

    def read_class(self, r, vers):
        n = r.u32()
        n2 = r.u32()
        value = r.u32()
        nprim = r.u32()
        nel = r.u32()
        ncons = r.u32()
        nm = r.raw(n).decode('utf-8', 'replace')
        comkey = None
        if n2:
            comkey = r.raw(n2).decode('utf-8', 'replace')
        tbl = dict(self.commons.get(comkey, {})) if comkey else {}
        for _ in range(nel):
            self.read_perm(r, tbl)
        self.read_constraints(r, ncons, False, vers)
        if vers >= 19:                      # POLICYDB_VERSION_VALIDATETRANS
            ncons2 = r.u32()
            self.read_constraints(r, ncons2, True, vers)
        if vers >= 27:                      # NEW_OBJECT_DEFAULTS
            r.u32(); r.u32(); r.u32()
        if vers >= 28:                      # DEFAULT_TYPE
            r.u32()
        self.classes[nm] = value
        self.class_val[value] = nm
        self.perms[value] = tbl

    def read_role(self, r, vers=None):
        n = r.u32()
        value = r.u32()
        if vers >= 24:                      # BOUNDARY
            r.u32()
        nm = r.raw(n).decode('utf-8', 'replace')
        r.ebitmap()                         # dominates
        r.ebitmap()                         # types
        self.roles[nm] = value

    def read_type(self, r, vers):
        n = r.u32()
        value = r.u32()
        if vers >= 24:
            prop = r.u32()
            bounds = r.u32()
        else:
            prop = r.u32()
            bounds = 0
        nm = r.raw(n).decode('utf-8', 'replace')
        self.types[nm] = value
        self.type_val[value] = nm
        self.type_prop[value] = (bool(prop & 1), bool(prop & 2), bounds)

    def read_user(self, r, vers):
        n = r.u32()
        value = r.u32()
        if vers >= 24:
            r.u32()
        r.raw(n)
        r.ebitmap()                         # roles
        if vers >= 19:                      # MLS
            # mls_read_range_helper: u32 items; items*u32 sens; ebitmap low; if items>1 ebitmap high
            items = r.u32()
            for _ in range(items):
                r.u32()
            r.ebitmap()
            if items > 1:
                r.ebitmap()
            # mls_read_level: u32 sens; ebitmap cat
            r.u32()
            r.ebitmap()

    def read_bool(self, r, vers=None):
        value = r.u32()
        state = r.u32()
        n = r.u32()
        nm = r.raw(n).decode('utf-8', 'replace')
        self.bools[nm] = (value, state)

    def read_sens(self, r, vers=None):
        n = r.u32()
        isalias = r.u32()
        nm = r.raw(n).decode('utf-8', 'replace')
        # mls_read_level: u32 sens; ebitmap cat
        r.u32()
        r.ebitmap()

    def read_cat(self, r, vers=None):
        n = r.u32()
        value = r.u32()
        isalias = r.u32()
        r.raw(n)

    # ---------- avtab ----------
    def read_avtab(self, r, vers):
        nel = r.u32()
        for _ in range(nel):
            src = r.u16()
            tgt = r.u16()
            cls = r.u16()
            spec = r.u16()
            if vers >= 30 and (spec & AVTAB_OP):
                r.u8()                      # ops.type
                for _ in range(8):          # operation_perm.perms[8]
                    r.u32()
                datum = 0
            else:
                datum = r.u32()
            self.avtab.append((src, tgt, cls, spec, datum))
        return nel

    # ---------- avtab 之后的段落 ----------
    def read_context(self, r, vers):
        user = r.u32()
        role = r.u32()
        typ = r.u32()
        if vers >= 19:                     # MLS
            items = r.u32()
            for _ in range(items):
                r.u32()
            r.ebitmap()
            if items > 1:
                r.ebitmap()
        return (user, role, typ)

    def skip_to_ocontext(self, r, vers, trace=False):
        # cond_read_list
        ncond = r.u32()
        if ncond:
            raise NotImplementedError('cond_list nel=%d (bools 非空，需要 cond_read_node)' % ncond)
        # role_trans
        nrt = r.u32()
        for _ in range(nrt):
            r.u32(); r.u32(); r.u32()
            if vers >= 26:
                r.u32()
        # role_allow
        nra = r.u32()
        for _ in range(nra):
            r.u32(); r.u32()
        # filename_trans
        nft = r.u32()
        for _ in range(nft):
            ln = r.u32()
            r.raw(ln)
            r.u32(); r.u32(); r.u32(); r.u32()
        if trace:
            sys.stderr.write('cond=%d role_trans=%d role_allow=%d filename_trans=%d off=0x%x\n'
                             % (ncond, nrt, nra, nft, r.o))
        return (ncond, nrt, nra, nft)

    def read_isids(self, r, vers, nocon=7):
        """只读 OCON_ISID 段（ocontexts 的第 0 组）"""
        isids = {}
        nel = r.u32()
        for _ in range(nel):
            sid = r.u32()
            ctx = self.read_context(r, vers)
            isids[sid] = ctx
        return isids

    # ---------- 主流程 ----------
    def load(self, path, trace=False, isids=False):
        d = open(path, 'rb').read()
        r = R(d)
        magic = r.u32()
        if magic != MAGIC:
            raise ValueError('bad magic 0x%x' % magic)
        slen = r.u32()
        s = r.raw(slen)
        vers = r.u32()
        config = r.u32()
        sym_num = r.u32()
        ocon_num = r.u32()
        self.vers = vers
        if trace:
            sys.stderr.write('magic ok, vers=%d config=0x%x sym_num=%d ocon=%d, off=0x%x\n'
                             % (vers, config, sym_num, ocon_num, r.o))
        self.policycaps = r.ebitmap()
        if vers >= 23:
            self.permissive_map = r.ebitmap()
        if trace:
            sys.stderr.write('policycaps=%s permissive_map=%s off=0x%x\n'
                             % (sorted(self.policycaps), sorted(self.permissive_map), r.o))

        readers = [self.read_common, self.read_class, self.read_role, self.read_type,
                   self.read_user, self.read_bool, self.read_sens, self.read_cat]
        # class 需要 vers
        for i in range(sym_num):
            nprim = r.u32()
            nel = r.u32()
            if trace:
                sys.stderr.write('symtab[%d] nprim=%d nel=%d off=0x%x\n' % (i, nprim, nel, r.o))
            for _ in range(nel):
                readers[i](r, vers)
        if trace:
            sys.stderr.write('symtabs done off=0x%x  types=%d classes=%d\n'
                             % (r.o, len(self.types), len(self.classes)))
        n = self.read_avtab(r, vers)
        if trace:
            sys.stderr.write('avtab entries=%d off=0x%x\n' % (n, r.o))
        self.end_off = r.o

        if isids:
            self.skip_to_ocontext(r, vers, trace)
            self.isids = self.read_isids(r, vers)
            if trace:
                sys.stderr.write('isids=%d off=0x%x\n' % (len(self.isids), r.o))
        return self

    # ---------- 查询 ----------
    def t(self, name):
        return self.types.get(name)

    def c(self, name):
        return self.classes.get(name)

    def perm_bit(self, cls, perm):
        v = self.classes.get(cls)
        if v is None:
            return None
        return self.perms.get(v, {}).get(perm)

    def allows(self, src_name, tgt_name, cls_name, perm_name):
        """只看 avtab 的 allow 位（不含 attribute 展开 / 不含 constraint）"""
        s = self.types.get(src_name)
        t = self.types.get(tgt_name)
        c = self.classes.get(cls_name)
        if s is None or t is None or c is None:
            return None
        bit = self.perms.get(c, {}).get(perm_name)
        if bit is None:
            return None
        mask = 1 << bit
        for (asrc, atgt, acls, spec, datum) in self.avtab:
            if acls != c:
                continue
            if not (spec & AVTAB_ALLOWED):
                continue
            if asrc != s or atgt != t:
                continue
            if datum & mask:
                return True
        return False


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    # 仓库根 = analysis/selinux 上溯两级；策略本体在 artifacts/ 下（不入库）
    dump = os.path.join(here, '..', '..', 'artifacts', 'device', 'partitions')
    sep = os.path.normpath(os.path.join(dump, 'sepolicy'))
    if not os.path.exists(sep):
        sys.stderr.write('sepolicy not found: %s\n' % sep)
        return 2

    args = sys.argv[1:]
    trace = '--trace' in args
    p = Policy().load(sep, trace=trace)

    if '--selftest' in args or not args:
        print('policyvers      : %d' % p.vers)
        print('policycaps      : %s' % sorted(p.policycaps))
        print('permissive_map  : %s (empty=%s)' % (sorted(p.permissive_map), not p.permissive_map))
        print('types           : %d' % len(p.types))
        print('classes         : %d' % len(p.classes))
        print('roles           : %d' % len(p.roles))
        print('bools           : %d' % len(p.bools))
        print('avtab entries   : %d' % len(p.avtab))
        print('avtab end off   : 0x%x' % p.end_off)
        print()
        for n in ('shell', 'init', 'kernel', 'tmpfs', 'shell_data_file', 'system_data_file',
                  'camera_data_file', 'su', 'system_server', 'untrusted_app'):
            v = p.types.get(n)
            print('  type %-22s = %s' % (n, ('0x%x' % v) if v is not None else '<absent>'))
        for n in ('file', 'dir', 'process', 'security', 'socket', 'fd', 'binder', 'lnk_file'):
            v = p.classes.get(n)
            print('  class %-22s = %s' % (n, ('0x%x' % v) if v is not None else '<absent>'))
        return 0

    if '--isids' in args:
        p2 = Policy().load(sep, isids=True, trace=trace)
        for sid in sorted(p2.isids):
            u, ro, t = p2.isids[sid]
            print('  sid %2d -> type=%-24s (user=%d role=%d type=%d)'
                  % (sid, p2.type_val.get(t, '?'), u, ro, t))
        return 0

    if '--dump-types' in args:
        for nm, v in sorted(p.types.items(), key=lambda x: x[1]):
            prim, attr, bounds = p.type_prop.get(v, (False, False, 0))
            print('%-45s %5d%s%s' % (nm, v, '  [attr]' if attr else '', '  [bounds]' if bounds else ''))
        return 0

    if '--query' in args:
        i = args.index('--query')
        if len(args) < i + 5:
            sys.stderr.write('usage: --query <src_type> <tgt_type> <class> <perm>\n')
            return 2
        src, tgt, cls, perm = args[i + 1:i + 5]
        for nm in (src, tgt):
            if p.types.get(nm) is None:
                print('type %s: ABSENT from policy' % nm)
        if p.classes.get(cls) is None:
            print('class %s: ABSENT' % cls)
            return 1
        bit = p.perm_bit(cls, perm)
        print('class %s = %s, perm %s = %s'
              % (cls, p.classes.get(cls), perm, ('bit %d' % bit) if bit is not None else 'ABSENT'))
        r = p.allows(src, tgt, cls, perm)
        print('avtab direct allow %s -> %s : %s : %s = %s'
              % (src, tgt, cls, perm, '<no such type/class/perm>' if r is None else r))
        return 0

    print('nothing to do; use --selftest / --dump-types / --query')
    return 0


if __name__ == '__main__':
    sys.exit(main())
