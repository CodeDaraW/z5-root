# SO-01H (Xperia Z5) 内核提权攻击面完整清单

> **📁 路径说明**：文中的 `bl/bl/`、`dump/`、`exploit/probe/` 等旧路径是写作当时的，
> 换算表见 [README.md](README.md)「路径对照」。标题里的文件名见同页「命名对照」。

调研日期：2026-11-07（第二轮实验更新）
设备：SO-01H / docomo Xperia Z5 / MSM8994 / Adreno 430
内核：`3.10.84-perf-gaba44f0`（2017-01-13 编译）· 无 KASLR · SELinux Enforcing
上下文：`uid=2000(shell)`，`u:r:shell:s0`

---

## 一、核心结论

1. **没有 KASLR**。dmesg 完整打印固定布局：`.text @ 0xffffffc000080000`（标准基址）、
   `.data @ 0xffffffc001615000`、vmalloc/modules 区全部固定。拿到写原语后
   `cred`、`selinux_enforcing` 地址可直接静态计算，不需要 info leak。
2. **SELinux 只封 socket 族，不封字符设备**。`/dev/kgsl-3d0`、`/dev/ashmem`、
   `/dev/binder` 均可 open，KGSL 的 ioctl 全放行。
3. **KGSL Dirty COW 变体 (c70b4f8) 已实测关闭**（见下），攻击面转向 ashmem/binder/AF_INET。

## 二、实测可达性（权威结果，openat() 探针）

| 入口 | 结果 | 说明 |
|---|---|---|
| `/dev/ashmem` | ✅ root:root 666 | 可 open |
| `/dev/binder` | ✅ root:root 666 | 可 open（3.10 binder，CVE-2019-2215 不适用） |
| `/dev/kgsl-3d0` | ✅ system:system 666 | open + ioctl 全通 |
| `/dev/ion` | ❌ EACCES | 660 system:system，shell 无组权限 |
| `/dev/diag` | ❌ 权限拒绝 | |
| DCCP/NETLINK/PACKET/蓝牙/AF_ALG socket | ❌ SELinux 拒 | avc: denied create, permissive=0 |
| UDP/TCP (AF_INET) | ✅ | IPv4 栈可达 |
| mq_open | ❌ | mqueue fs 不可用 → CVE-2017-11176 排除 |

## 三、KGSL 通道最终结论（aarch64 原生探针，kgsl2~12.S 系列实验）

**ioctl 表与 copyleft 分支完全一致**（kgsl9 组合扫描确认）：
- `0xC0200910` ISSUEIBCMDS / `0xC0080913` DRAWCTRT_CREATE / `0xC0300915` MAP_USER_MEM /
  `0xC0300934` GPUMEM_ALLOC_ID / `0xC0480936` GPUMEM_GET_INFO / `0x40200937` SYNC_CACHE
  （SYNC_CACHE 是 `_IOW` 方向位 0x40，不是 0x80）
- DRAWCTRT_CREATE flags=0x12 成功；ISSUEIBCMDS 真实提交成功（ret=0）
- **GPU 取指/执行链路完全打通**（dmesg 证实 `ib1 30000000` 被 GPU 执行）

**Dirty COW 变体关闭证据链**：
1. MAP_USER_MEM(memtype=ADDR, USE_CPU_MAP) 对任意页成功建立 GPU 映射（GET_INFO 返回
   flags=0x10000060 = USE_CPU_MAP|USERMEM_ADDR，**无 GPUREADONLY**）。
2. GPU 读该映射 ✅（IB 被取指执行）；**GPU 写该映射 → IOMMU Permission Fault**
   （FSR=0x80000008=PF, write fault @ 30001000），对 anon RW 页同样如此 →
   设备二进制对 USERMEM 类映射强制 GPU 只读（vendor 加固，已修 c70b4f8 利用路径）。
3. GPU 写 kernel 分配内存（GPUMEM_ALLOC_ID, gpuaddr=0x1000）→ **零 fault，写入正常**
   → 排除"全局禁写"假设，加固仅针对 USERMEM 类。
4. CPU 侧写穿路径同样堵死：ADDR entry `memdesc.ops=NULL` → `get_mmap_entry` EINVAL
   → 对 /dev/kgsl 的 mmap 不可用（kgsl11/kgsl12 双验证）。
5. m5 大小: mmapsize 返回 0x2000（数据页+尾部 guard page），guard 逻辑与 copyleft 一致。

**结论：Sony 固件二进制（2016-07 构建）已包含比 copyleft dump 新的高通加固补丁。
c70b4f8 变体在设备上不可利用。** kernel-exact 源码仅作结构参考，与二进制有偏差。

## 四、当前主攻方向：CVE-2017-8890 (Phoenix Talon) —— 已实测触发成功

**触发链全部打通**（exploit/probe/mctest.c + join2.c）：
1. `socket(AF_INET, SOCK_STREAM)` ✅ SELinux 放行（UDP4/TCP4/UDP6/TCP6 全可建）
2. `setsockopt(SOL_IP, MCAST_JOIN_GROUP=42, group_req 136B, ifindex=1)` ✅ 成功
   - 注意: `IP_ADD_MEMBERSHIP(35)` 对 TCP socket 被 `is_icsk` 检查拒绝 (EPROTO)
   - `struct group_req` = 4+pad4+sockaddr_storage(128) = **136B**, gr_group@8
   - `struct ip_mreqn` = 12B (multiaddr@0, ifindex@8) —— 两者布局不同
3. `bind(127.0.0.1:4444)+listen` ✅ → `fork+connect` → `accept` ✅
   （newsk 经 sock_copy 继承父 mc_list 指针 —— 漏洞核心）
4. `close(newsock); close(srv)` → **ip_mc_socklist 被 kfree_rcu 两次 → double free** ✅
   （dmesg 无异常 = SLUB 无 debug，静默可利用）

**漏洞存在性证据**（kernel-exact 对照）：
- `inet_csk_clone_lock`/`sk_clone_lock` 无 `mc_list=NULL` 清理（上游修复 6548f7e 未含）
- `af_inet.c:407` 仅在新建 socket 时初始化 mc_list
- 影响范围 Linux 2.5.69~4.11，修复 2017-05 → 设备 2017-01 内核未含 ✓

**利用有利条件**：
- **无 KASLR**（dmesg 固定布局）→ `selinux_enforcing`/`init_task` 静态定位
- **无 PAN/PXN**（/proc/cpuinfo Features 无 pan；3.10 内核无 SW_PAN）→ **ret2usr 可用**，
  RCU 回调 func 可直接指向用户态代码，无需绕过 gadget
- 两次 free 时机可控（RCU 宽限期窗口）→ 堆喷占位窗口充足
- 公开利用先例：Nexus 6P 3.10 / Android 7.x（thinkycx, freebuf, xz.al）

**利用方案**（参考公开 exploit 本机化）：
1. double free `ip_mc_socklist` (kmalloc-96)
2. 堆喷 `ipv6_mc_socklist`（前 8 字节 in6_addr 用户可控）占位
3. RCU 回调时劫持 `rcu.func` → 用户态函数（内核态执行）
4. 内核态代码：写 `selinux_enforcing=0` + 修改当前进程 cred → uid=0

**待办**：
- [ ] 精确计算偏移：ip_mc_socklist.rcu 偏移（kernel-exact/include/net/ip_mc_socklist? linux/igmp.h）
- [ ] 定位 init_task/selinux_enforcing 精确地址（.data 扫描签名法，dmesg 有 .data 基址）
- [ ] task_struct.cred/comm 偏移计算（3.10.84 头文件手动 offsetof）
- [ ] 堆喷稳定性（bind_on_cpu + 多次重试）

## 五、已排除路线（完整清单）

| 路线 | 结论 |
|---|---|
| CVE-2016-5195 Dirty COW 主漏洞 | ❌ 已修复（2017-01 固件 backport；cowtest.c 实测：/proc/self/mem 写 RO 映射仅产生 COW 副本，文件未被改） |
| KGSL Dirty COW 变体 c70b4f8 | ❌ 设备二进制已加固：GPU 侧 USERMEM 映射强制只读（IOMMU PF fault），CPU 侧 mmap 被 ops=NULL 堵死 |
| F2FS 族 (CVE-2017-0750/10662/10663) | ❌ 需要 mount 权限 |
| ION | ❌ 节点不可达（EACCES） |
| qseecom/smem_log/ttyHSL0/smd0/uinput | ❌ SELinux 拒（EACCES，avc 实证） |
| mq/DCCP/PACKET/netlink/蓝牙 | ❌ SELinux 拒或 fs 不存在 |
| CVE-2017-7308 (packet socket) | ❌ 需 CAP_NET_RAW |
| CVE-2019-2215 | ❌ binder 版本不符 |
| /sys/fs/selinux/policy 读策略 | ❌ read_policy 被拒（avc） |
| perf_event_paranoid 读取 | ⚠️ 文件可读（值未确认，perf_event_open 未测） |

## 六、候选漏洞（更新中）

| # | 漏洞 | 状态 | 触发入口 | 备注 |
|---|---|---|---|---|
| 1 | ~~c70b4f8 Dirty COW 变体~~ | ❌ 已实测关闭 | — | 见第三节 |
| 2 | ~ade62c8 GPU 地址范围检查缺失~ | ⚠️ 疑似受同批加固影响 | MAP_USER_MEM | 需要重新评估 |
| 3 | 2017-08 ASB 内核 fs 族：CVE-2017-10661 (高, A-36266767)、CVE-2017-0750/10662/10663 | 待定位具体子系统 | fs | SPL 2017-01 未含 |
| 4 | 3.10 stable v3.10.85~v3.10.100 上游修复全扫 | 待做 | — | 对照 kernel-exact 逐一确认 |

被排除：CVE-2017-11176（mq）、CVE-2017-1000251（蓝牙）、CVE-2017-6074/8824（DCCP）、
CVE-2019-2215（binder 版本不符）、ION 全族（节点不可达）、CVE-2017-7308（packet socket
需 CAP_NET_RAW，SELinux 已拒 create）。

## 五、工具资产

- `exploit/probe/mkelf.py` —— 无 NDK/Rosetta 的 aarch64 ELF 构建管线（仅 .text，数据必须内联）
- `exploit/probe/kgsl*.S` —— KGSL 探针系列（kgsl9=ioctl 扫描器, kgsl10/11/12=写权限判别）
- `exploit/probe/open_probe.S` —— 设备节点 open+errno 探针
- `kernel-exact/` —— sonyxperiadev/kernel 32.1.F.1.xxx 分支（结构参考，与设备二进制有加固偏差）
- `logs/boot-dmesg.txt` —— 开机日志（固定内存布局证据）
- `tools/newflasher` —— arm64 原生刷机工具（备用路线）

## 六、下一步

1. 定位 2017-08 ASB 内核 fs 族四个 CVE 的具体子系统与修复 commit，逐一对照 kernel-exact。
2. 全量拉取 upstream linux-3.10.y v3.10.85→v3.10.100 的 changelog，筛出 shell 域可触发的 LPE。
3. 扩展 /dev 节点枚举（qseecom/qcedev/vidc 等 Qualcomm 驱动）+ 读取关键 sysctl
   （perf_event_paranoid、dmesg_restrict、kptr_restrict）。
