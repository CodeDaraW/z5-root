# 构建 newflasher（arm64 macOS 原生）

## 现状

`tools/newflasher` **已经是可用的 Mach-O arm64 原生二进制**（v61），无需 Rosetta / Java / sudo：

```bash
file tools/newflasher
# tools/newflasher: Mach-O 64-bit executable arm64

./tools/newflasher            # 会打印 libusb 初始化日志并等待设备
```

> **注意**：这个二进制**不在 git 里**（仓库只收源码）。新克隆的仓库需要按本文下半部分
> 自行编一次，或从旧工作目录拷贝。源码 `tools/newflasher.c` 与 `tools/version.h` 是在库的。

用途：**免解锁刷索尼签名固件**（对应已放弃的 C 线，ADR 0002）。
它同时是本机唯一"可能"的现场恢复候选，但**从未在实机上验证过刷写**。

## 为什么是自编译

原版 newflasher / Flashtool 只提供 Linux/Windows 的 x86 二进制；
arm64 macOS 上跑不了 x86（无 Rosetta 时），也没有 `brew` / `sudo` 可用，所以从源码原生编。

## 组成

| 文件 | 说明 |
|---|---|
| `tools/newflasher.c` | munjeni/newflasher v61 源码（141KB），`version.h` 提供版本号 |
| `tools/libusb-1.0.27/` | libusb 源码树 + **手写 `config.h`** + 已编好的 `libusb-1.0.a`（**整目录不入 git**，需重新下载上游 + 按下文重建 `config.h`） |
| `tools/newflasher` | 产物（**不入 git**） |
| `tools/libusb.tar.bz2` | 原始源码包（**不入 git**；上游 libusb 1.0.27 可重新下载） |

## 关键技巧：绕开 autotools

`./configure` 在收尾阶段会调用 `rm`，在禁用 `rm` 的受限 shell 里 configure 必然失败。
解决办法是**不跑 configure**，手写 `config.h`（`tools/libusb-1.0.27/config.h` 即为成品），
然后用 clang 直接编译那 9 个 `.c`（core.c / descriptor.c / hotplug.c / io.c / linux_usbfs 不适用，
macOS 走 `darwin_usb.c`），最后 `ar` 打包成静态库。

## 重建步骤（⚠️ 未逐条复验）

**前置**：`tools/libusb-1.0.27/` 整个目录不入库，干净克隆要先解包上游源码：

```bash
cd tools && tar xjf libusb.tar.bz2     # 或从 libusb 上游取 1.0.27
```

然后把下面这份 `config.h` 原样写到 `tools/libusb-1.0.27/config.h`
（**别跑 `./configure`**，见上一节）：

```c
/* Hand-written config.h for libusb 1.0.27 on macOS arm64. */
#define PLATFORM_POSIX 1

#define USE_POSIX_THREADS 1
#define USE_POSIX_EVENT 1

#define HAVE_SYS_TIME_H 1
#define HAVE_PTHREAD_H 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_CLOCK_GETTIME 1
#define HAVE_NFDS_T 1
#define HAVE_STRUCT_TIMESPEC 1

#define API_EXPORTED __attribute__((visibility("default")))
#define DEFAULT_VISIBILITY __attribute__((visibility("default")))
#define PRINTF_FORMAT(a, b) __attribute__((__format__(__printf__, a, b)))

#define ENABLE_LOGGING 1
#define ENABLE_DEBUG_LOGGING 1

#define LIBUSB_VERSION_MAJOR 1
#define LIBUSB_VERSION_MINOR 0
#define LIBUSB_VERSION_MICRO 27
#define LIBUSB_VERSION_NANO 0
```

```bash
REPO=/path/to/repo          # 本仓库根，按实际位置填
cd "$REPO/tools/libusb-1.0.27"
# 1) 编译（macOS 后端），.o 落在当前目录
clang -c -O2 -I. -Ios Darwin/*.c \
      core.c descriptor.c hotplug.c io.c strerror.c sync.c os/events_posix.c \
      os/threads_posix.c libusb-1.0.def 2>/dev/null
# 2) 打静态库
ar rcs libusb-1.0.a *.o
# 3) 编 newflasher（回到 tools/）
cd "$REPO/tools"
clang -o newflasher newflasher.c -Ilibusb-1.0.27/libusb \
      libusb-1.0.27/libusb-1.0.a \
      -framework IOKit -framework CoreFoundation -framework Security -lz -lexpat
```

这段没有在 2026-11-21 的整理中重跑（当时的产物已在位，且重编会覆盖可用二进制）。
**如果只是要用，直接用现成的 `tools/newflasher`；只有当它跑不起来时才需要重建。**

## 用法要点

```bash
REPO=/path/to/repo          # 本仓库根
# 只备份 TA、不刷任何东西（安全，推荐先做这一步）
cd <固件目录> && "$REPO/tools/newflasher" Dump-trim-area
# 产物：tadump/tadump_1.ta, tadump_2.ta

# 刷整个目录（⚠️ 目录里所有 .sin/.ta 都会被刷进去，先清场）
"$REPO/tools/newflasher"
```

## 坑

- 目录里**所有文件都会被刷**，跑之前务必把不相关文件移走。
- 手机需先进 **flash mode**（关机 → 按住音量下 → 插 USB → 绿灯）。
- 提示 `keep userdata?` → 降级场景选 `n`（清空）。
- 刷的是**索尼签名的官方固件**，签名不符会在 flash 阶段被拒（不会刷成砖）。
