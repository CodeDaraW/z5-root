# 当前状态

> 最后更新：2026-11-21（整理仓库时据 `research/` 长文回溯整理，未新增实验）
> 这台文档是唯一的"现在时"文档，其余长文都是某个时间点的快照。

## 一句话

**root 拿到了（临时、非持久），bootloader 解不开（判定为密码学死路），
项目从"攻"转成"存档 + 等一个线下动作（docomo SIM 解锁）"。**

## 设备

| 项 | 值 |
|---|---|
| 型号 | SO-01H（docomo 版 Xperia Z5，代号 sumire） |
| 平台 | MSM8994 / arm64-v8a / Adreno 430 |
| 系统 | Android 6.0.1 / API 23，构建 `32.1.F.1.98` |
| 内核 | `3.10.84-perf-gaba44f0`（2017-01-13 编译） |
| 安全补丁 | 2017-01-01 |
| SELinux | Enforcing（user 版，非 userdebug） |
| /system | `/dev/block/dm-0`，dm-verity **确认启用** |
| BL 状态 | 锁定；`fastboot oem unlock` → `Command not allowed` |

## 已经拿到的

### A. 内核提权（成功，可分发）

- **一条链打通到 uid=0**：CVE-2017-8890（Phoenix Talon）double free → RCU 回调劫持 →
  内核态改写 `cred` + `selinux_enforcing`。
- **做成一键 APK**（`apps/z5root`，包名 `com.z5.root`）：点一下 → 15 秒倒计时 →
  20~80 秒出结果，自带 3 次重试与崩溃后续跑（`BootReceiver` + `pending.txt`）。
- **su 落点** `/mnt/su`（`-rwsr-sr-x root root`，tmpfs），另一份客户端 `/data/local/su`。
- **验过第三方可用**：任意 app `Runtime.exec("/mnt/su -c id")` 得 `uid=0` + 满 caps
  （`apps/sutest` 是验证用的最小 app）。
- **已知代价**：root 在位期间 SELinux 为 Permissive、`panic_on_oops=0`；
  **重启即失效**（干净的失效，`/mnt/su` 随 tmpfs 消失）。

### B. BL / TA 侧（研究完成，结论为"不可行"）

- 21 个 BL 分区完整 dump（`artifacts/bootloader`，52MB）。
- **TA 记录格式定案**：`[uid u32][size u32][magic 0x3BF8E9C1][flags u32][data][对齐填充]`，
  全盘 2082 条，外部用 `tad` 服务的权威尺寸校验过 **1962 个可读 unit 逐字节一致**。
- **TAD 协议破译**：`adb forward` 直连 `/dev/socket/tad`，**无需 root** 即可只读访问 TA
  （社区少见，`analysis/ta/tadif.py` 可直接复用）。
- **bootconfig（unit `0x84F`）解码完成**：1ACE 容器，6 条 TLV 零残留，**内不含任何 rooting 字段**。
- **三张证书的身份**：`0x851`=S1_SL（SimLock）、`0x1046C`=S1_RLock（Remote Lock）、
  `0x7D3`=S1_HWConf（分区描述表），均由 `S1_Root_f936` 签发。
- **dm-verity 全链闭环**：表 → root → 顶块 → L1 → L0 → 数据块五级哈希全部重算命中
  （`analysis/verity/verify_verity.py` 可复跑，六次比较全部 MATCH、退出码 0）。
- **aboot 解锁判定链还原到指令级**：真正的判定在 `0x3E043040` 读组件表 bit1，
  code 校验被**外包给外部 S1 服务**（即刷机工具），设备端**不验签**。

## 已经判死的

| 路线 | 依据 | ADR |
|---|---|---|
| 改 TA 里的 `ROOTING_ALLOWED="0"` | 那只是显示层；真判定读组件表 | [0007](decisions/0007-bl-unlock-is-key-not-code.md) |
| 改 `0x7DA` / 改 `0x1046C` | `0x1046C` 是自包含签名 blob，改一字节必失效；`0x7DA` 与 `0x851` 一起送校验，**覆盖范围未证实**，但无恢复入口，仍按不写处理 | [0008](decisions/0008-never-write-0x7da-or-0x1046c.md) |
| 伪造 SIM 解锁状态 | 与 `ROOTING_ALLOWED` 同一份签名 blob | 同上 |
| 持久化 root（改 /system） | `MNT_LOCK_READONLY` + 块层 ro + dm-verity 三重墙 | [0001](decisions/0001-temporary-root-only.md) |
| 免解锁降级刷 2016 固件 | 缺 FTF；且 root 已由 A 线达成 | [0002](decisions/0002-abandon-official-downgrade.md) |
| KGSL Dirty COW 变体 | 设备二进制已加固：GPU 侧 USERMEM 强制只读（IOMMU PF） | [0003](decisions/0003-pick-phoenix-talon-not-kgsl.md) |

## 还没闭合的

| # | 事项 | 价值 | 风险 | 成本 |
|---|---|---|---|---|
| 1 | **docomo SIM 解锁（线下）** —— 唯一还没试的合规路径，可能连带打开 rooting 门 | 高 | 零 | 需日本/代理解锁 |
| 2 | `0x1046B` 那 16 字节 nonce 与 IMEI 的关系（纯离线） | 低（仍缺服务端签名） | 零 | 半天 |
| 3 | 设备当前在线状态、`/mnt/su` 是否仍可复现 | 维护性 | 零 | 10 分钟 |

> 曾经列过第 4 项「`tad` 的 `write` op 权限边界」——已撤下。测它必然写 TA，
> 而本机没有恢复链，属于下面第 1 条纪律的禁区，不是"待办"。

## 硬性纪律（不要绕过）

1. **不写 TA。** 本机**没有可用的现场恢复入口**：fastboot flash 被拒、EDL 需签名 programmer、
   flash mode + newflasher 从未验证过。写坏 TA = 变砖且无法自救。
   历史上唯一一次单字节写入是日志槽测试，已原样还原。
2. **设备数据不入库。** TA 含 IMEI 与 DRM keys，分区镜像含机器唯一标识。
3. **BL 这条线不要再投入逆向工时。** 瓶颈已从"代码/格式"移到了"密钥"，见
   [`research/bl-conclusions.md`](research/bl-conclusions.md) §11.9。
