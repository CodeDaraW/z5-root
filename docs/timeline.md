# 迭代史

按轮次记录"做了什么、为什么转向、错在哪"。只追加，不改写历史节。
早期细节在 `history/工作日志.md`（2724 行）与 `history/交接文档_2026-11-09.md`（614 行），
本文是它们的压缩版 + 之后 BL 阶段的编年。

时间轴总览：

| 轮次 | 日期 | 主题 | 结果 |
|---|---|---|---|
| R0 | 11-07 白天 | 免解锁降级刷机 | ⛔ 缺 FTF，悬置 |
| R1 | 11-07 | 内核攻击面测绘 + KGSL 试验 | 排除 KGSL，选定 Phoenix Talon |
| R2 | 11-08 ~ 11-11 | exploit 落地、SELinux 之争、APK 成型 | ✅ L1 达成 |
| R3 | 11-11 | BL 分区导出、TA 初探、verity | 三堵墙模型 + verity 定案 |
| R4 | 11-11 晚 | 双模型交叉复审（GLM） | verity 布局破译 |
| R5 | 11-12 | TAD 协议、记录格式勘误、签名验证 | ROOTING_ALLOWED 定位 |
| R6 | 11-13 | 全量比对、官方路径、收费工具机制 | ❌ BL 判定不可行 |
| R7 | 11-21 | 仓库整理（本次） | 代码/文档/资产分层 |

---

## R0 · 免解锁降级刷机（11-07 白天）

**假设**：锁 BL 下不能刷 boot/recovery，但能刷**索尼签名的官方固件**（.sin + .cms，与 BL 锁无关）。
所以：降到 Dirty COW（CVE-2016-5195）未修复的固件（补丁早于 2016-10）→ `run-as` 提权。

**做成的**：刷机工具链。受限环境里 `brew`/`sudo` 不可用、没有 Rosetta、没有系统 Java，官方 x86 二进制全跑不了，
于是从源码原生编译出 **Mach-O arm64 的 newflasher v61**；libusb 的 `configure` 依赖 `rm`（受限 shell 里被拦），
改成手写 `config.h`，clang 直接编 9 个 `.o`。已验证能启动、能枚举 USB。

**卡住的**：固件。需要 E6653/SO-01H、构建 `32.1.A.1.163` 一类、补丁 < 2016-10 的 `.ftf`。
索尼官方 API 只给最新版；archive.org 无 Z5 条目；2016 年论坛/GDrive/Mega 链接全失效。

**结局**：悬置。随后 R1 换思路（不改固件，直接打内核），并在 R2 拿到 root 后**正式放弃**。

**产物**：`tools/newflasher`（arm64 原生）、`tools/libusb-1.0.27`、`artifacts/firmware/`（失败的下拉记录）。

---

## R1 · 内核攻击面测绘 + KGSL 试验（11-07）

**动作**：从设备 dump 关键资产——`kimg.bin`(32MB)、`kallsyms`、`sepolicy`(300KB)、
`file_contexts`、内核 config、开机 dmesg。用 aarch64 原生探针（无 NDK，`mkelf.py` 手搓 ELF）逐个探。

**三个基础事实**（后来所有判断都建立在这三条上）：
1. **无 KASLR**：dmesg 打印固定布局，`.text @ 0xffffffc000080000`，拿到写原语就能静态算出 `cred`、
   `selinux_enforcing` 地址，**不需要 info leak**。
2. **SELinux 只封 socket 族，不封字符设备**：`/dev/kgsl-3d0`、`/dev/ashmem`、`/dev/binder` 都能 open。
3. **无 PAN/PXN**：3.10 内核，`ret2usr` 可用，RCU 回调可以直接指向用户态代码。

**KGSL 路线判死**（kgsl2~12 系列探针）：ioctl 表与 copyleft 一致，GPU 取指/执行链路打通
（dmesg 证实 IB 被 GPU 执行），但：
- GPU **写** USERMEM 类映射 → IOMMU Permission Fault（对 anon RW 页同样）；
- CPU 侧 mmap 被 `memdesc.ops=NULL` 堵死；
- GPU 写 kernel 分配的 GPUMEM 正常 → 说明加固只针对 USERMEM 类，不是全局禁写。

即 **c70b4f8 变体在设备二进制上已修复**，`kernel-exact` 源码只是结构参考（与二进制有偏差）。

**转向 CVE-2017-8890（Phoenix Talon）**：`MCAST_JOIN_GROUP` + `accept()` 让 `newsk` 继承父 socket 的
`mc_list` 指针 → 双双 close → `ip_mc_socklist` 被 `kfree_rcu` 两次。触发链全部实测打通
（注意 `group_req` 是 136B，`IP_ADD_MEMBERSHIP` 对 TCP 会被 `is_icsk` 拒）。

**产物**：`analysis/probes/device/`（196 份 .c/.S 探针）、`artifacts/device/partitions/`。
（R7 整理时只保留最终 4 份源码，其余按 `probes.md` 的谱系删除。）

---

## R2 · exploit 落地与 SELinux 之争（11-08 ~ 11-11）

这是最长、最曲折的一轮。**核心认知**后来被总结成一句话：
> 难点不在拿 uid 0，而在拿到之后**别把 SELinux 拆坏**。

**三次弯路**（代价排序，来自外部复盘 `research/root-retrospective.md` §A.2）：

1. **probe55 设计时没读完 `security_load_policy()` 的分支**：清 `ss_initialized` 再回灌会触发
   **sidtab 重建**。由此引出十几小时的 relabel 补丁、"相机硬件坏了"的误诊、SystemUI 崩溃循环。
   教训：把任何"奇技"当地基之前，读完它调用的**所有**函数的源码，尤其分支结构。
2. **日志基建晚了约 18 小时**：SELinux 封掉一切 syscall 通道时，用"共享匿名页 + fork 抄写员"
   （约 30 行）才拿到日志。此前"竞速连续 5 次失败""进程卡死"相当一部分是**仪器问题**
   （真相是竞速全赢了只是看不见；"卡死"其实是 `sleepms` 的 `tv_nsec=1e9` 返回 EINVAL）。
3. **用 live 实验回答静态问题**：Q1/Q2 的答案早就躺在 `/sepolicy`（307KB）与 `kimg.bin`（32MB）里。

**路线 G（init 域策略热加载）的兴衰**：外部复盘提出的"最优解"，看起来同时满足 sidtab 无损、
打标签照常、重启零残留。但 `sepolicy_parse.py` 落地后**两小时证伪**：user 版策略对
`load_policy` / `setenforce` **零授权**（那条授权只存在于 userdebug 基线）。
→ 方法论赢了：**静态可答的问题不上机**，这条纪律后来救了数不清的设备实验。

**关键转折（§19.8）**：既然 permissive 拿不到，就走**纯授权内的 relabel 链**——
`type_transition` + `relabelto` + shell execute，零 permissive、零内核写、零 sidtab 风险。

**最后的卡点与两行修复**（R2 末，外部复审 Part N）：
- 爆点一：`process_keyring = 0x100000001`。第 3 写 + 第 6 写的副作用（`sl_count++`）拼出野指针，
  `prepare_creds()` 里的 `key_get()` 直接对未映射地址 `atomic_inc` → oops。
  修法 A：六写完成后在用户态把假 cred 的 `0x58/0x5c` 清 0（假 cred 本就在 RW 映射里）。
- 爆点二：`commit_creds()` 第一行 `BUG_ON(task->cred != task->real_cred)`。
  这不是"嫌疑"而是**定理**——`override_creds()` 的定义就是只改 `task->cred`。
  修法 B：`fork()` 走 `copy_creds()`，子进程 `cred = real_cred` 天然一致，绕开 BUG_ON。

**结果**：`apps/z5root` 成型（一键、3 次重试、崩溃续跑），L1（adb 可用 su）达成。
L2（第三方 app 免授权调用）用 `/mnt/su` 也顺手达成，代价是**不做弹窗确认**。

---

## R3 · BL 分区导出、TA 初探、verity（11-11）

**动作**：借临时 root 窗口（开机后约 18 秒出现 `/mnt/su`）只读 dump 21 个分区 → `artifacts/bootloader/`。

**fastboot 侧**：`getvar all` 被裁到 7 个变量（Sony 刻意不暴露解锁状态）；
`oem unlock 0x00…0` 在**解析 code 之前**就返回 `Command not allowed` → 门在策略层，不是"码不对"。

**TA 侧**：TA 分区**没有加密**（熵 1.94 bits/byte，78% 为零），记录明文可解析；
TA 不是静态分区——每次开机 SBL1 往尾部写启动日志（两次 dump 差 12,686 字节，全在 `0x802–0x806` 日志槽）。

**写能力**：`mmcblk0p1` 权限 `tad:tad 660`、`ro=0`、SELinux Permissive → 理论上整盘 dd 可写。
做了**单字节可判别测试**（`0x7b001`，`0x22 → 0x31`），整盘比对只有 1 字节变化，随后原样还原。

**三堵墙纠错（v1 → v2，重要）**：v1 说"`mount(2)` 整体被拒"是**错的**。
实测：新建 tmpfs、自建挂载 remount、umount 全部成功；被拒的只是"不保留现有标志的 rebind-remount"
（裸 remount 会剥掉 `nosuid,nodev`，撞 `MNT_LOCK_NODEV/NOSUID`）。`MNT_LOCKED` 在 3.10.84 **不存在**。
`/system` 真正的三堵墙 = `MNT_LOCK_READONLY`（硬）+ 块层 ro（`BLKROSET` 可清，软）+ **dm-verity**。

**verity 定案**：fstab `wait,verify` + `/verity_key` + `partition.system.verified=1` + dm-0 比 p44 短 43MB，
四条独立证据。→ "verity 缺失则运行时改 /system"这条乐观分支关闭。

---

## R4 · 双模型交叉复审（11-11 晚）

引入第二个模型（GLM）做对抗评审，产出 `research/bl-review.md`（465 行）。价值极高，因为它**证伪了我**：

- 证伪"`mount(2)` 整体被拒"，给出真机制（`MNT_LOCK_NODEV/NOSUID` 锁族，`fs/namespace.c:1820/1830`）。
- **破译 verity 尾部之谜**：magic `0xb001b001` 在**数据区末尾**块 1,335,440（Android 6 布局，不是
  ChromeOS 的分区尾）；哈希树 **root-first**；尾部 705KB 重复值 V **不是 root**，
  而是 `sha256(salt‖4096×00)`（带盐零块哈希）；重复区其实是 L0 尾部。

随后我对 GLM 的结论做了一次**独立复核**（`verify_verity.py` 可复跑），五级链全部命中，同时修正它三处数字
（L0 块数 10,434 而非 10,433；尾部填充 339,968B/83 块 而非 343,552B；唯一异词=数据块 #1,310,720）
与一处结构误判（元数据不是"1 块 + 7 块 PKCS#7"，实测块 1..7 全零；块 0 = magic + version + **256B raw RSA 签名**
+ u32 表长 238 + 表）。

**留下的未解**：`/verity_key` 是 524B 非 PEM/DER 二进制，穷举全部 256B 窗口作模数都不出合法 PKCS#1 填充
→ 签名公钥来源未定（不影响"verity 已启用"这个结论）。

---

## R5 · TAD 协议、记录格式勘误、签名验证（11-12）

**TAD 协议破译**（本轮最有复用价值的产出）：`adb forward tcp:19999 localfilesystem:/dev/socket/tad`
（`adbd` 在 `trimarea` 组 2993）。请求 `[u32 len+9][u8 ver=1][u32 a0][u32 op][payload]` 全大端，
op 0=open(payload=`[mode,1]`)/2=getsize/3=read/4=write。**无需 root** 就能只读 TA。
服务端对安全 unit 做可见性过滤（`0x7DA/0x84F/0x851` 返回 `Unit not found`，普通 unit 正常）。

**记录格式勘误（推翻 v4）**：正确布局是 `[uid][size][magic][flags][data][fill]`——**uid/size 在 magic 之前**。
旧解析把首尾读反，导致每条 unit 内容整体错位一条，污染了此前所有"某 unit 里是什么"的判断。

**`0x84F` 是合法 bootconfig**（97B，`1A CE 28 00`），不是时间戳；6 条 TLV 恰好耗完 97B；
**内不含任何 rooting 字段** → "改 bootconfig 换解锁"无收益。

**`ROOTING_ALLOWED` 真正位置 = unit `0x7DA`**（639B），不是 `0xA2A`。
它被 `0x851`（`CN=S1_SL`）的 RSA-2048 签名覆盖。

**离线验签**：`0x851` = `[20B 头][691B 证书][3B 02 01 00][256B 签名]` = 970，严丝合缝；
用证书公钥解出**合法 PKCS#1 v1.5 / SHA-256 DigestInfo** → 签名真实。
但被签消息未复现（`0x7DA` 全子区间 + 全盘 2082 unit × 8 种形态，10,022 组全不命中）。

---

## R6 · 收口：从"签名覆盖范围"到"缺一把钥匙"（11-13）

**全量外部验证**（设备重连后补齐）：
- 2070 个 uid 中 1962 个设备可读，**尺寸 100% 一致、内容逐字节相同、0 差异** → 记录格式升为【实测】。
- 无漏记录；`tad` 拒绝的 108 个单元是**权限**不是缺失（含 DRM provisioning）。
- 坑：机密 unit 返回 `Unit not found(4)` 而不是 `Operation not allowed`，
  所以"`0x8B2` 本机不存在"这个旧结论**用 tad 无法证实**。

**两处自我更正**：
- `0x3E0429B0` **不是验签函数**，被调目标是节点表操作（按 id 计数/取值/取数据），**没有 hash update**。
  → "三件套一起验签"应改为"三件套一起送进后续处理"。
- `0x3E049F04` 不是 rooting 专用解析器，是**通用 kv 查找**（`memcpy("ROOTING_ALLOWED",15)` 做 key）。

**GLM 第三/四轮复审带来的新事实**：
- 三件套函数有**两个调用者**：fastboot 侧 `0x3E03D3CC` 与**开机判定路径 `0x3E03E88C`**
  → "只在 fastboot 读"的前提作废，每次开机都读 `0x7DA/0x851`。
- 开机路径对三件套失败是**优雅降级**（打印 `S1 decisions failed...` 继续启动），
  真正 bootcrash 的是另一道固件映像签名检查 → 单字节扰动无 brick 路径。
- 实验判据应换成**响应文本**：gate 翻开时裸 `oem unlock` 会从 `Command not allowed`
  变成 `Incorrect format for unlock data...`，零 wipe 风险。
- `0x7b001` 在 uid `0x803`（不是 `0x804`）；写入是 `0x22 → 0x31`（不是 `0x30 → 0x31`），
  因为我们错把 `TA.img`（隔了一次重启）当"写前"基线。

**官方解锁路径的代码级还原**：三层锁/三张证书；判据是一张 16 位位图
（`[ctx+0x58]+0x1C`，**bit1 = rooting 允许**，bit12 = override，且 override 只打日志、不改控制流）。

**收费解锁工具的机制（终局）**：
- 设备端解析路径**完全不验签**（`0x3E043A54` 只做 4 个结构检查，末尾证书"只存不校"）。
- 真正的门是 `ctx+0x44` 的**外部 S1 服务句柄**，通过 `blx [r5,#0x2c]` 回调插件函数。
  固件里三句话坐实："Please start your flashing tool…" → **S1 服务 = 外部刷机工具**。
- 本机实际状态：`0x1046B` 有 16B nonce（非空 = 解锁请求走到过一半）；
  `0x1046C` 是 1042B SIN 容器，**由 S1_Root_f936 根私钥直签**，内容是 docomo 锁定数据。
- 结论：**缺的不是代码/格式/算法，是私钥**。收费工具卖的是"持有签名"，不是"绕过"。

**净结论**：BL 这条线在 aboot 侧逆向到底了。剩下唯一合规路径是 docomo SIM 解锁（线下）。

---

## R7 · 仓库整理（11-21，本次）

没有任何新实验，纯工程整理：

- 根目录 20+ 个散落文件按 `docs / apps / analysis / artifacts / tools / vendor` 分层。
- 把整理前散落在旧工作区的代码与资产全部收进来：
  APK 源码、`exploit/probe`（196 份探针）、`dump/`（kallsyms/sepolicy/kimg）、`report/`（验收日志与截图）。
- 脚本内的硬编码路径（`bl/bl/TA.img` 等）改为基于仓库根定位，并**跑通冒烟测试**
  （`ta_parse2.py` 输出 2082 条记录；`verify_verity.py` 六次比较全部 MATCH）。
- APK 离线构建链路验证可复现（`apps/z5root/build.sh` → `build/signed.apk` 25,169B）。
- 补齐 `docs/status.md`、`timeline.md`（本文）、`pitfalls.md`、`glossary.md`、10 条 ADR 与操作手册。
- 设备私有数据（TA/分区镜像）加 `.gitignore`，避免 IMEI 与 DRM keys 入库。

### R7.1 · 收紧入库范围（同日，接手前整理）

**判据**：git 只收"人能读、能审、能复现"的东西。删掉后能否用仓库里的源码 + 文档重建？
能 → 不入库。

- **二进制移出 git**：`apps/z5root/assets/{z5root,su}`（aarch64 裸 ELF）、
  `tools/newflasher`（Mach-O）、`tools/libusb.tar.bz2`、`analysis/ta/bootcfg_84f.bin`、
  `apps/z5root/z5.keystore`。新增 `apps/z5root/build-assets.sh`，重编产物与
  2026-11-11 的二进制**逐字节一致**（sha256 `806d511d…` / `f683d784…`），所以删得掉。
- **探针剪枝 171 → 4**：只留 `probe_app.c`（APK 版）、`probe149s.c`（adb 版）、
  `z5c.c`、`capchk.c`（+ `mkelf.py` / `go.sh`）。中间版本彼此只差几个偏移，
  留着会被误当成"可用版本"。谱系与死因写进 `docs/probes.md`。
- **隐私清理**：IMEI 与设备序列号从全部文档中移除（不打码，直接不写这个字段），
  历史提交一并重写；本机工作记录目录（编辑器/助手产生）整目录不入库。
