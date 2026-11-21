#!/usr/bin/env python3
"""把 clang 产出的 aarch64 可重定位目标文件包装成可执行的静态 ELF。

用途：macOS 上没有 ld.lld，无法用 clang 直接链接出 aarch64 的 ELF 可执行文件。
这里绕过链接器：从 .o 里抽出全部可装载段（.text + .rodata.*），应用 .rela.text
重定位，手工拼出 ELF64 头和单个 PT_LOAD 段。
前提：源码自包含（不引用外部符号），无全局数据（.bss/.data 需另行处理）。
输出：符号运行时地址表（供 exploit 硬编码 payload 地址等）。
"""
import struct
import sys

BASE = 0x10000
CODE_OFF = 64 + 56          # ehdr + phdr
PAD = (8 - CODE_OFF % 8) % 8
CODE_BASE = BASE + CODE_OFF + PAD   # 第一个段（.text）第 0 字节的运行时地址

# aarch64 重定位类型（经 clang 实测校准）
R_ADR_PREL_LO21 = 274
R_ADR_PREL_PG_HI21 = 275
R_TSTBR14 = 279
R_CONDBR19 = 280
R_ADD_ABS_LO12 = 277
R_JUMP26 = 282
R_CALL26 = 283
R_LDST8 = 278
R_LDST16 = 284
R_LDST32 = 285
R_LDST64 = 286
R_LDST128 = 299

LDST_SCALE = {R_LDST8: 0, R_LDST16: 1, R_LDST32: 2, R_LDST64: 3, R_LDST128: 4}

SHT_PROGBITS = 1
SHT_NOBITS = 8
SHF_ALLOC = 0x2


def main(path, out):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF" or d[4] != 2:
        raise SystemExit("需要 ELF64 目标文件")
    e_shoff, = struct.unpack_from("<Q", d, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x3A)

    def sh(i):
        return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)

    st_off, st_size = sh(e_shstrndx)[4], sh(e_shstrndx)[5]
    shstrtab = d[st_off:st_off + st_size]

    secs = []
    for i in range(e_shnum):
        s = sh(i)
        n = s[0]
        name = shstrtab[n:shstrtab.index(b"\0", n)].decode()
        secs.append((name, s))

    symtab = next((s for n, s in secs if s[1] == 2), None)   # SHT_SYMTAB
    if not symtab:
        raise SystemExit("找不到 .symtab")
    strtab_off, strtab_size = sh(symtab[6])[4], sh(symtab[6])[5]
    strtab = d[strtab_off:strtab_off + strtab_size]

    def sym_name(idx):
        return strtab[idx:strtab.index(b"\0", idx)].decode()

    # ---- 1. 布局：收集全部可装载段（.text/.rodata/.data 为 PROGBITS，.bss 为 NOBITS）----
    loadable = []           # [(sec_index, name, sh)]
    for i, (name, s) in enumerate(secs):
        if not name.startswith(".eh_frame") and (s[2] & SHF_ALLOC) and \
                s[1] in (SHT_PROGBITS, SHT_NOBITS) and name not in (".note.GNU-stack",):
            loadable.append((i, name, s))
    if not loadable:
        raise SystemExit("找不到可装载段")

    # .text 必须排第一（entry 指向 _start = .text[0]），NOBITS(.bss) 排最后
    loadable.sort(key=lambda x: 0 if x[1] == ".text" else (2 if x[2][1] == SHT_NOBITS else 1))
    if loadable[0][1] != ".text":
        raise SystemExit(".text 缺失")

    runtime_base = {}       # sec_index -> 运行时地址
    image = bytearray()
    off = CODE_OFF + PAD    # 段数据在文件内的起始偏移（= CODE_BASE - BASE）
    for _, name, s in loadable:
        align = max(1, s[8])  # sh_addralign
        while (off + len(image)) % align:
            image += b"\0"
        runtime_base[_] = CODE_BASE + len(image)
        if s[1] == SHT_NOBITS:
            data = b"\0" * s[5]                     # .bss 零填充
        else:
            data = d[s[4]:s[4] + s[5]]
        image += data
        print("  load %-18s off=%#x  size=%#x  runtime=0x%x%s" %
              (name, len(image) - len(data), len(data), runtime_base[_],
               " (.bss)" if s[1] == SHT_NOBITS else ""))

    # ---- 2. 符号表（注意：条目必须与 .symtab 原始索引一一对应，勿预置占位）----
    syms = []               # syms[i] = (name, shndx, value, type)，i 即原始符号索引
    for i in range(symtab[5] // 24):
        st_name, st_info, _, st_shndx, st_value, _ = \
            struct.unpack_from("<IBBHQQ", d, symtab[4] + i * 24)
        syms.append((sym_name(st_name), st_shndx, st_value, st_info & 0xF))

    def sym_runtime(idx):
        name, shndx, value, _ = syms[idx]
        if shndx == 0:
            raise SystemExit("引用了外部符号，无法静态打包: %s" % name)
        if shndx not in runtime_base:
            raise SystemExit("符号 %s 所在段不可装载 (shndx=%d)" % (name, shndx))
        return runtime_base[shndx] + value

    # ---- 3. 应用 .rela.text 重定位 ----
    text_si = loadable[0][0]
    code = bytearray(d[secs[text_si][1][4]:secs[text_si][1][4] + secs[text_si][1][5]])
    relocs = 0
    for name, s in secs:
        if not name.startswith(".rela.text"):
            continue
        cnt = s[5] // 24
        for i in range(cnt):
            r_off, r_info, r_add = struct.unpack_from("<QQq", d, s[4] + i * 24)
            rtype = r_info & 0xFFFFFFFF
            S = sym_runtime(r_info >> 32)
            P = CODE_BASE + r_off
            A = r_add
            insn = struct.unpack_from("<I", code, r_off)[0]
            if rtype == R_ADR_PREL_PG_HI21:
                imm = (((S + A) & ~0xFFF) - (P & ~0xFFF)) >> 12
                imm &= 0x1FFFFF
                insn = (insn & ~(0x1FFFFF << 5)) | ((imm & 3) << 29) | ((imm >> 2) << 5)
            elif rtype == R_ADR_PREL_LO21:
                imm = ((S + A) - P) & 0x1FFFFF
                insn = (insn & ~(0x1FFFFF << 5)) | ((imm & 3) << 29) | ((imm >> 2) << 5)
            elif rtype in (R_TSTBR14, R_CONDBR19):
                delta = (S + A) - P
                if rtype == R_TSTBR14:
                    imm = delta & 0x3FFF          # imm14 @ [18:5]
                    insn = (insn & ~(0x3FFF << 5)) | (imm << 5)
                else:
                    imm = delta & 0x7FFFF         # imm19 @ [23:5]
                    insn = (insn & ~(0x7FFFF << 5)) | (imm << 5)
            elif rtype == R_ADD_ABS_LO12:
                insn = (insn & ~(0xFFF << 10)) | (((S + A) & 0xFFF) << 10)
            elif rtype in LDST_SCALE:
                imm = ((S + A) & 0xFFF) >> LDST_SCALE[rtype]
                insn = (insn & ~(0xFFF << 10)) | (imm << 10)
            elif rtype in (R_JUMP26, R_CALL26):
                imm = (((S + A) - P) >> 2) & 0x3FFFFFF
                insn = (insn & ~0x3FFFFFF) | imm
            else:
                raise SystemExit("未支持的重定位类型 %d @ .text+%#x" % (rtype, r_off))
            struct.pack_into("<I", code, r_off, insn)
            relocs += 1

    # ---- 4. 打包（.text 数据回填进镜像）----
    tb = runtime_base[text_si] - CODE_BASE
    image[tb:tb + len(code)] = code
    filesz = CODE_OFF + len(image)
    # 入口 = _start 符号（.text 首函数不一定是 _start，例如多了一个辅助函数时）
    entry = CODE_BASE
    for i, (name, shndx, value, _) in enumerate(syms):
        if name == "_start" and shndx in runtime_base:
            entry = sym_runtime(i)
            break
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr += struct.pack("<HHIQQQIHHHHHH",
                        2, 183, 1, entry, 64, 0, 0,
                        64, 56, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 7, 0, BASE, BASE, filesz, filesz, 0x1000)
    with open(out, "wb") as f:
        f.write(ehdr + phdr + bytes(image))
    print("wrote %s  entry=0x%x  image=%d bytes  relocs=%d" % (out, entry, len(image), relocs))
    for i, (name, shndx, value, _) in enumerate(syms):
        if shndx and shndx in runtime_base and name:
            print("  %-24s 0x%x" % (name, sym_runtime(i)))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit("用法: mkelf.py <input.o> <output>")
    main(sys.argv[1], sys.argv[2])
