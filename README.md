# SO-01H（Xperia Z5）root 与 BL 解锁研究

一台 docomo 版 Sony Xperia Z5 的所有权范围内的安全研究记录：
**内核提权成功了，bootloader 解锁被判定为密码学死路。**

> 仅供本机、本人设备的研究与可恢复性验证。结论强依赖固件版本（`32.1.F.1.98` / 内核 `3.10.84`），
> **不要套用到其他机型或版本**。仓库内含可用的提权实现，请自行评估使用场景。

| 项 | 值 |
|---|---|
| 设备 | SO-01H / docomo Xperia Z5（sumire）/ MSM8994 |
| 系统 | Android 6.0.1，构建 32.1.F.1.98，安全补丁 2017-01-01 |
| 内核 | `3.10.84-perf-gaba44f0`（无 KASLR、无 PAN/PXN） |
| 现状 | **临时 root 可用**（重启失效）；**BL 锁定，判定无法解锁** |

## 三条线，三种结局

### ✅ A · 内核提权 → 一键 root APK

CVE-2017-8890（Phoenix Talon）：`accept()` 继承父 socket 的 `mc_list` → 双 close →
`kfree_rcu` double free → 劫持 RCU 回调 → 内核态改写 `cred` 与 `selinux_enforcing`。

做成了可分发 APK：点一下，15 秒倒计时后开始，20~80 秒出 `★ 成功: su 已就位`。
自带 3 次重试与崩溃后续跑（UAF 阶段约 40% 概率触发一次黑屏重启，开机自动续上）。

```bash
cd apps/z5root && bash build-assets.sh   # 从源码编出两个 aarch64 裸 ELF（不入 git）
cd apps/z5root && bash build.sh          # 打包 → build/signed.apk
adb install -r build/signed.apk
adb shell /mnt/su -c id                  # uid=0(root)
```

代价：root 在位期间 SELinux 为 Permissive、`panic_on_oops=0`；**重启即干净失效**。
细节见 [`docs/guides/apk-usage.md`](docs/guides/apk-usage.md)。

### ❌ B · BL 解锁 → 缺一把钥匙

六轮假设依次推翻后，落在一个很干净的结论上：

> 设备端**完全不验签**，真正的判定外包给"外部 S1 服务"（即官方刷机工具），
> 而解锁数据由 `S1_Root_f936` 的**根私钥直签**。
> **缺的不是代码、格式或算法，是那把私钥。**

副产品（都有独立价值）：TA 记录格式完全解出（2082 条，与设备逐字节一致）、
**TAD 私有协议破译（无 root 即可只读 TA）**、bootconfig 解码、dm-verity 哈希树五级闭环复现、
aboot 解锁判定链还原到指令级。

详见 [`docs/research/bl-conclusions.md`](docs/research/bl-conclusions.md)。

### ⛔ C · 免解锁降级刷机 → 缺固件

降到 Dirty COW 未修复的 2016 固件。工具链已原生编出（Mach-O arm64 的 newflasher），
但 2016 年的 `.ftf` 全网找不到。已被 A 线取代。

## 从这里开始

| 你想 | 去 |
|---|---|
| 接手这个项目 | [`AGENTS.md`](AGENTS.md) → [`docs/README.md`](docs/README.md) |
| 知道现在什么状态 | [`docs/status.md`](docs/status.md) |
| 看历史怎么走过来的 | [`docs/timeline.md`](docs/timeline.md) |
| 少踩坑 | [`docs/pitfalls.md`](docs/pitfalls.md)（26 条） |
| 复跑关键检查 | [`docs/guides/reproduce.md`](docs/guides/reproduce.md)（每项都写明输入从哪来） |
| 连设备、读 TA | [`docs/guides/device-access.md`](docs/guides/device-access.md) |

## 仓库结构

```
docs/        文档（结论 / 过程 / 总结三层，见 docs/README.md）
apps/        z5root（一键 root APK 源码）、sutest（验证用最小 app）
analysis/    ta / aboot / verity / selinux 分析脚本；probes 只留最终 exploit 源码
artifacts/   设备导出数据（TA、21 个 BL 分区、内核与策略）—— 不入 git
tools/       离线构建链（JDK17 + Android cmdline-tools + 手编 libusb）+ newflasher 源码
vendor/      第三方源码树（kernel-exact 等）—— 不入 git
```

**仓库只追踪源码与文档**：编译产物（`assets/*`、`newflasher`、`*.o`、`*.apk`、`keystore`）
都能用仓库内源码重建，因此不进 git；设备私有数据与 100MB+ 镜像同理。
171 个探针只保留最终 4 份，失败版本的去向见 [`docs/probes.md`](docs/probes.md)。

## 几个可复跑的"硬结果"

```bash
python3 analysis/ta/ta_parse2.py            # records=2082，三条短记录尺寸与 tad 权威值一致
python3 analysis/verity/verify_verity.py    # 表→root→顶块→L1→L0→数据块，6 次比较全部 MATCH
```

`artifacts/` 为空时这些跑不了——设备数据不入库（TA 含 IMEI/DRM keys），
重建方式见 [`artifacts/README.md`](artifacts/README.md)。

## 纪律

- **不写 TA**：本机没有可用的现场恢复入口，写坏即变砖且无法自救。
- **不写 `0x7DA` / `0x1046C`**：签名真实，改了必被拒。
- **不写设备唯一标识**：IMEI、序列号、SIM 卡号、账号信息一律不出现（不打码，直接不写）。
- 结论分级标注【实测】/【强推断】/【推测】；被推翻的段落保留并加删除线，不删。
