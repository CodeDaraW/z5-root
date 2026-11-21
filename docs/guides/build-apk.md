# 构建一键 root APK

**完全离线**，不依赖 Android SDK / Gradle / NDK。链路是：
`javac(JDK17) → D8(r8.jar) → 手写 AXML → zip 组包 → jarsigner(v1)`。

## 一次构建

```bash
cd apps/z5root
bash build-assets.sh     # 先编 assets/z5root 与 assets/su（产物不入 git，见下节）
bash build.sh            # 产物：build/signed.apk（约 25KB）
adb install -r build/signed.apk
```

2026-11-21 复验输出（本次整理仓库后重跑）：

```
== 1) javac (--release 8)
== 2) D8 -> classes.dex          classes.dex 17760 bytes
== 3) AndroidManifest.xml (AXML) 1864 bytes
== 4) 组包                        build/unsigned.apk 22926 bytes
== 5) 签名                        build/signed.apk  25169 bytes
```

> 25169 vs 发布的 25170 差 1 字节，来自 zip 内时间戳，可忽略。

## 工具链（不在 git 里，首次克隆必须另行准备）

| 依赖 | 路径 | 说明 |
|---|---|---|
| JDK 17 (macOS arm64) | `tools/jdk17/Contents/Home` | 提供 `javac / jarsigner / keytool / java` |
| r8.jar | `tools/sdk/cmdline-tools/latest/lib/r8.jar` | 提供 D8（dex 转换） |
| Android stubs | `apps/z5root/stubs/` | 手写的 `android.*` 空实现，只为过 javac |
| AXML 生成器 | `apps/z5root/tools/axml.py` | 手写二进制 AndroidManifest |

这些工具**不在 git 里**（合计约 460MB）。**干净克隆不能直接构建**——先按下文
"重建离线工具链"把两样东西放进 `tools/` 再跑构建命令。本页记录的复验是在已有工具链的
机器上做的；"从零把工具链摆好再构建"这一步**尚未在干净环境验证过**。

## 结构

```
apps/z5root/
├── build.sh                构建总入口（5 步）
├── build-assets.sh         从源码编 assets/ 下两个 aarch64 裸 ELF
├── src/com/z5/root/
│   ├── MainActivity.java    UI + 倒计时 + exploit 拉起 + 重试
│   └── BootReceiver.java    开机续跑（读 pending.txt，上限 3 次）
├── assets/
│   ├── z5root               exploit 主程序（arm64 ELF，**生成物，不入 git**）
│   └── su                   4064B 静态 su（**生成物，不入 git**）
├── stubs/                   android.* 桩
├── tools/axml.py            AndroidManifest.xml 二进制封装
├── z5.keystore              v1 签名密钥（首次 build.sh 自动生成，不入 git）
└── build/                   构建输出（.gitignore）
```

## 两个 ELF 资产怎么来的

`assets/z5root` 与 `assets/su` 是**二进制，不在 git 里**，由 `build-assets.sh` 现编：

| 产物 | 源码 | 编译方式 |
|---|---|---|
| `assets/z5root` | `analysis/probes/device/probe_app.c` | `clang --target=aarch64-linux-gnu -O2 -ffreestanding -fno-builtin -nostdlib -fno-stack-protector -c` → `mkelf.py` |
| `assets/su` | `analysis/probes/su/su.c` | 同上 |

不用 NDK 的原因：会链进 libc，体积到几 MB，还要处理动态链接器路径。这里编成
freestanding 的 `.o`，再由 `mkelf.py` 抽出可装载段、应用重定位、手拼 ELF64 头
（macOS 上没有 `ld.lld`，无法直接链出 aarch64 ELF）。

**可复现性已验证**：重编产物与 2026-11-11 打进 APK 的二进制逐字节一致——

```
z5root  sha256 806d511d5a7f0c631614dac4d11124d71e9615096ba17d62669609f34f63745c  33584 B
su      sha256 f683d784f4a6382abb8fff3ab8668479bb19748badcf18ba4d15745e1c242f64   4064 B
```

对不上就是 clang 版本或编译参数变了，先 diff 参数再怀疑源码。

## 坑

- `JAVA_HOME` 必须指到 `tools/jdk17/Contents/Home`，脚本已按 `../../tools` 算好相对路径；
  **如果你又挪了目录，只改 `build.sh` 第 6 行 `TOOLS=`**。
- `build.sh` 用 `python3 -c "shutil.rmtree('build', True)"` 清输出目录（不依赖 `rm`，
  在禁用 `rm` 的受限 shell 里同样可用，别改回 `rm -rf`）。
- `assets/su` 是**静态、4064 字节、04755**。它只是守护进程的客户端，守护进程不在就明确拒绝，
  所以留在 `/data/local/su` 无害。
- 签名必须是 v1（JAR signing）：Android 6.0 不校验 v2，而离线环境没有 apksigner。

## 重建离线工具链（若 `tools/jdk17|sdk` 丢了）

1. JDK 17 macOS arm64（Temurin）解包到 `tools/jdk17`。
2. Android `cmdline-tools` 解包到 `tools/sdk`，`r8.jar` 在 `cmdline-tools/latest/lib/`。
3. 两者都只被 `build.sh` 引用，无其他耦合。

## 相关

- 使用说明（给最终用户）：[`apk-usage.md`](apk-usage.md)
- exploit 原理与事故史：[`../research/root-retrospective.md`](../research/root-retrospective.md)
