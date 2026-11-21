# apps/z5root —— 一键 root APK

包名 `com.z5.root`。构建产物 `build/signed.apk`。用法见 [`../../docs/guides/apk-usage.md`](../../docs/guides/apk-usage.md)，
构建细节见 [`../../docs/guides/build-apk.md`](../../docs/guides/build-apk.md)。

## 构建（两条）

| 脚本 | 作用 |
|---|---|
| `build-assets.sh` | 用 clang + `mkelf.py` 从 `analysis/probes/device/probe_app.c`、`analysis/probes/su/su.c` 编出两个 aarch64 裸 ELF → `assets/` |
| `build.sh` | 五步打包（桩编译 → R8 → axml → zip → 签名）→ `build/signed.apk` |

`assets/` 里的两个二进制与 `*.keystore` 不入库，但**逐字节可复现**，见 `../../docs/pitfalls.md`。

## 设备侧验收脚本

这些脚本是**在一台真机上跑过的验收与取证工具**，不是构建链的一部分。
全部要求 `adb` 已连上设备，输出统一落到 `../../artifacts/reports/`（该目录不入库）。

| 脚本 | 用途 | 何时用 |
|---|---|---|
| `finalcheck.sh` | 交付前一次干净安装 + 冷启动验收（不触发 / 触发后两组取证）。`./finalcheck.sh reboot` 走完整冷启动 | 改完 APK 要签字时 |
| `accept.sh` | 多轮冷启动验收：拿到 root 用时、期间是否重启（uptime 归零）、重试次数 | 要统计成功率时 |
| `bootcheck.sh` | 干净态体检：不重启、不触发，确认系统是原厂状态 | 怀疑 root 残留时 |
| `unroot_proof.sh` | **从 app 域**证明 root 在不在。`adb shell` 跑 `/mnt/su` 重启后照样返回 0，会误判——判据必须走 app 域 | 验证"重启即失效" |
| `soak.sh` | root 在位长稳：每 3 分钟抽查关键子系统，`./soak.sh 60` | 长时间观察 |
| `soak2.sh` | 干净态长稳（不触发 root） | 同上，对照组 |
| `shellprobe.sh` | 冷启动后跑 **shell 版** exploit 并抓 kmsg | 调试 shell 通路 |
| `shelltest.sh` | 同上，但盯 `rep.bin` 的精确进度，`./shelltest.sh <exploit名> [秒]` | 调试卡在哪一步 |
| `w2hunt.sh` | 反复跑 shell 版直到 dmesg 出现 oops，抓写 `cap_bset` 的崩溃栈 | 定位 UAF 崩溃点 |
| `panicprobe.sh` | 反复触发直到抓到一次完整 panic dmesg | 同上，抓全量 |

### 已删除的脚本

`coldtest.sh` / `coldtest2.sh` / `run_app.sh` 是同一段"冷启动 → 点图标 → 查 root"逻辑的三次迭代，
差别只有 `sleep` 秒数和轮询次数，已被 `finalcheck.sh` 与 `accept.sh` 完全覆盖，故删除（git 历史里可取回）。
