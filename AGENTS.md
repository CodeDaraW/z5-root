# AGENTS.md · 接手须知

给下一个 coding agent / 人类协作者的入口。**先读完这一页再动手。**

## 这个项目是什么

对**一台** Sony Xperia Z5 / SO-01H（docomo, Android 6.0.1, 构建 32.1.F.1.98, 内核 3.10.84）
做 root 与 bootloader 解锁的安全研究。三条线索，状态完全不同：

| 线 | 状态 | 还能做什么 |
|---|---|---|
| A. 内核提权（CVE-2017-8890） | ✅ 成功，已做成 APK | 维护、复现、可移植性讨论 |
| B. BL 解锁（TA / aboot 逆向） | ❌ 判定不可行（缺 S1 根私钥） | **不要再投入逆向工时** |
| C. 免解锁降级刷机 | ⛔ 放弃（缺 2016 FTF） | 除非拿到固件，否则不动 |

**当前唯一有意义的推进方向**是线下的 docomo SIM 解锁（见 `docs/status.md` "还没闭合的"）。

## 先读这些（顺序别换）

1. `docs/README.md` —— 文档地图与权威性规则（哪份文档说了算）
2. `docs/status.md` —— 一页现状：做到了什么、判死了什么、下一步
3. `docs/pitfalls.md` —— **26 条踩过的坑**，能省你一天
4. `docs/decisions/` —— 10 条 ADR，每个"不做了"背后的证据
5. `docs/probes.md` —— 171 个探针试过什么、死在哪（失败版本的源码已删，这里是唯一索引）
6. 需要细节时查 `docs/research/`；`docs/history/` 是史料，别当结论

## 仓库地图

```
docs/           文档（结论层 / 过程层 / 总结层，见 docs/README.md）
  status.md       唯一"现在时"文档（新结论的最终落点；改的顺序见「文档」一节）
  timeline.md     迭代史，只追加
  pitfalls.md     坑清单，可续写
  glossary.md     术语（TA / SIN / S1_* / verity / cred …）
  decisions/      ADR，编号递增，旧的不删
  guides/         可执行手册：build-apk / build-newflasher / device-access / reproduce
  research/       技术长文（带版本号与时效标记）
  history/        原始工作日志（只读）
apps/
  z5root/         一键 root APK 源码（Java + 手搓 AXML + 离线构建链）；12 个验收/取证脚本见同目录 README.md
  sutest/         验证用的最小 app（证明第三方可调用 su）
analysis/
  ta/             TA 记录解析、TAD 客户端、bootconfig 解码、被拒 unit 重扫（ta_reject_scan.py）
  aboot/          ARM 反汇编辅助与交叉引用
  verity/         dm-verity 全链校验、签名穷举
  selinux/        sepolicy 解析、权限查询、锚点扫描
  probes/         最终 exploit 源码（probe_app / probe149s / z5c / capchk）+ mkelf.py
                  失败版本已删，索引见 docs/probes.md
artifacts/        设备导出数据（**不入 git**，见 ADR 0009）
tools/            离线构建链（jdk17/sdk/libusb/newflasher）与 newflasher 源码
vendor/           第三方源码树（**不入 git**）
scripts/device/   设备端 dump 脚本
```

## 硬性红线（违反会造成不可逆后果）

1. **不写 TA。** 本机没有可用的现场恢复入口（fastboot 被拒 / EDL 需签名 programmer /
   flash mode 从未验证）。详见 ADR 0005。
2. **不写 `0x7DA` / `0x1046C`。** 签名真实，改完必被拒——不是"风险高"而是"必然失败"。ADR 0008。
3. **设备数据不入 git。** TA 含 IMEI 与 DRM keys。`.gitignore` 已排除 `artifacts/`，别用 `-f` 强加。
4. **文档里不写设备唯一标识。** IMEI、设备序列号、SIM 卡号、MAC、账号名一律不出现——
   不打码、不写掩码，直接不提这个字段。仓库可能公开，写了就是永久泄漏。
5. **二进制与「设备派生物」不入 git。** 判据：删掉后能否用仓库里的源码 + 文档步骤重建？
   能就不入库。所以 `assets/*`、`tools/newflasher`、`*.bin`、`z5.keystore`、
   以及 `artifacts/ta/security_units.txt`（重扫就有）这类都不追踪。
   目标是**别人拿代码能自己跑出结果**，而不是看到我这台机器的值。
6. **不要为了"看一眼"去重启进 fastboot。** `getvar` / `oem unlock`（不带有效 code）是零风险的，
   但设备重启会丢掉临时 root 窗口，后续要做的事全得重来。
7. **不要 kill 名为 `z5root` 的进程**（持着 UAF socket，退出可能 panic 重启）。
8. **不要采信"设备端行为"在 Permissive 状态下测出的结果** —— 那是 root 的副作用。

## 工程约定

### 脚本

- **分析脚本一律用 `python3`**，无第三方依赖（`capstone` 除外：`arm_dis.py` 需要它）。
  例外是构建与设备验收：`apps/*/build.sh`、`apps/z5root/*.sh` 是 bash/zsh——
  它们本质是一串 adb 命令，用 Python 反而更难读。
- **路径必须基于仓库根定位**，不要写 `bl/bl/TA.img` 这类历史相对路径。模板：

  ```python
  import os
  REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
  ```

  （`analysis/<topic>/x.py` → 上溯三级即仓库根；`artifacts/` 在根下）
- 只读脚本默认安全；任何会写设备的脚本，必须在文件头写清"写入什么、恢复方式"。

### 文档

- 中文，短句，先结论后证据。
- 每个技术判断带可信度标记：**【实测】/【强推断】/【推测】**，不带标记的段落默认视为过程记录。
- 结论变更的正确顺序：**先改 `docs/research/` 长文并升版本号 → 再同步 `docs/status.md` / `timeline.md`**。
- 被推翻的段落**不要删**，加 `~~删除线~~` + `【已被 §x.x 推翻，见 …】`。这是本项目的核心资产（ADR 0010）。

### 新增一轮工作

1. `docs/timeline.md` **追加**一节（编号顺延），写清：目标 / 动作 / 结论 / 自我纠错 / 产物。
2. 有新决策 → `docs/decisions/NNNN-slug.md`。有变卦 → 新增 ADR 并标注 `supersedes 00xx`。
3. 踩了新坑 → `docs/pitfalls.md` 对应类别，三段式：症状 → 根因 → 正确做法。
4. 结论有变 → 按上面「文档」一节的顺序改（长文 → `status.md`），别只改一处。

## 常用命令

```bash
# APK 构建（离线）；在仓库根执行。工具链不在 git 里，首次克隆先照 docs/guides/build-apk.md 准备
(cd apps/z5root && bash build-assets.sh && bash build.sh)   # → apps/z5root/build/signed.apk ≈25KB

# 冒烟测试（离线，在仓库根执行，应有确定输出）
python3 analysis/ta/ta_parse2.py           # 配置区 1962 条；总数约 2082（日志区随开机次数变）
python3 analysis/verity/verify_verity.py   # 6 次比较全部 MATCH，退出码 0
python3 analysis/ta/bootcfg_decode.py analysis/ta/bootcfg_84f.bin   # 6 条 TLV 零残留（该 .bin 不入库，需先从 TA 取 unit 0x84F）

# 需要设备（见 docs/guides/device-access.md）
adb forward tcp:19999 localfilesystem:/dev/socket/tad
(cd analysis/ta && python3 ta_verify_live.py)   # 1962 unit，0 差异
python3 analysis/ta/ta_reject_scan.py           # 被拒 unit 清单（本机私有，别提交）
```

完整复现清单与期望输出：`docs/guides/reproduce.md`。

## 环境坑

- 工作区的 shell 沙箱**禁用 `rm`**（安全策略）。要删东西就移到系统废纸篓，或
  在构建脚本里用 `python3 -c "shutil.rmtree(...)"`，别改回 `rm -rf`。
- 不依赖系统包管理器：`sudo` / `brew` 一律没有，JDK、SDK、libusb 都是仓库内自带的。
- `tools/newflasher` 是 Mach-O arm64 二进制，可直接跑（会打印 libusb 调试日志，正常）。
  它**不在 git 里**，新克隆需按 `docs/guides/build-newflasher.md` 重编（clang + libusb 源码）。

## 写代码之前先问的三个问题

1. **这个问题的答案是不是已经在磁盘上了？**（`artifacts/` 里有 kimg、sepolicy、TA dump、21 个分区）
   —— 用 live 实验回答静态问题是本项目最大的时间浪费源（`pitfalls.md` 第 17 条）。
2. **我改的这个东西，改了算不算数？**（信任锚在哪：签名、verity、SELinux 域）
   —— "能写进去"和"写了有效"是两件事（第 24 条）。
3. **观测手段建好了吗？** —— 没有可靠日志通道的进攻性实验，失败原因无法归因（第 16 条）。
