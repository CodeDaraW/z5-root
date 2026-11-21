# SO-01H 免解锁 root 方案记录

## 设备实况（实测）

| 项目 | 值 |
|---|---|
| 型号 | SO-01H（docomo 版 Xperia Z5，sumire） |
| 系统 | Android 6.0 / API 23，构建 32.1.F.1.98 |
| 内核 | 3.10.84-perf-gaba44f0，2017-01-13 编译 |
| 安全补丁 | 2017-01-01 |
| 架构 | arm64-v8a（MSM8994） |
| SELinux | Enforcing |
| 当前权限 | uid=2000(shell)，无 su，ro.debuggable=0，user 版 |
| /system 挂载 | /dev/block/dm-0（dm-verity 开启） |
| CDA / 定制 | 1299-6036 / R22C，DOCOMO-LTECA |
| 解锁位 | sys.oem_unlock_allowed=1（但官方无解锁码） |
| 其他 | build.fingerprint 为 user/dev-keys，shell 在 trimarea 组，带 docomo 3LM MDM 配置 |

## 方案原理

锁 BL 下无法刷 boot/recovery，只能走 flash mode 刷**索尼签名的官方固件**（.sin + .cms 校验，与 BL 锁无关）。

因此路径为：**降级到 Dirty COW（CVE-2016-5195）未修复的固件 → run-as 提权拿 root shell**。

- Dirty COW 的修复进入 Android 是 2016-11 安全公告，所以目标固件的补丁必须 **早于 2016-10**。
- 当前 2017-01 补丁已修复，必须降级。
- 3.10.84 上没有其他现成可跑的提权链（Bad Binder 需 3.18+ 的 binder epoll；后续 CVE 链均针对 GKI 6.x）。

### 持久化预期

`/system` 走 dm-verity，verity 开关在 boot.img 的 ramdisk 里，锁 BL 改不了 → **大概率只能拿到临时 root**（重启失效，每次开机 adb 重跑一次）。
若降到的老固件本身没开 verity（/system 直接挂块设备），则可 remount rw 做持久化 —— 刷完用 `mount | grep system` 实测。

## 已完成：刷机工具链

受限环境里 `brew` 与 `sudo` 均不可用（arm64 Mac、无 Rosetta、无 Java，Flashtool/newflasher 的官方 x86 二进制都跑不了）。改为从源码原生编译：

- `tools/libusb-1.0.27/` —— 手写 config.h 绕开 autotools（configure 依赖 rm，受限 shell 里被拦），clang 直接编 9 个 .o，打包成 `libusb-1.0.a`
- `tools/newflasher` —— munjeni/newflasher v61，**Mach-O arm64 原生二进制**，无需 Rosetta / Java / sudo

已验证可正常启动、libusb 可枚举 USB 设备。

## 待解决：固件（当前唯一阻塞项）

需要的文件特征：

- 型号：`E6653`（Z5 国际单卡）或 `SO-01H`（docomo 原厂）
- 构建号：`32.1.A.1.163` / `32.1.A.1.185` 一类（2016 上半年）
- 补丁级别：**早于 2016-10**
- 形式：`.ftf`（zip 封装 .sin+.cms）

已排查且失败的渠道：

- 索尼官方 API（app.swup.update.sony.net）—— 接口活着，但只提供当前/最新固件，不提供 2016 存档；且新接口需 CDFId + Sony Product Code + 内部 UUID
- archive.org —— 有 Xperia 固件合集，但无 Z5/E6653 条目
- 2016 年论坛/GDrive/Mega 旧链接 —— 不可靠

## 拿到 FTF 后的操作

```bash
# 1. 解压 FTF（本质是 zip）
mkdir -p firmware/extracted && cd firmware/extracted
unzip ../XXX.ftf

# 2. 手机进入 flash mode：关机，按住音量下，插 USB，绿灯
# 3. 刷入（会把 newflasher 放到固件目录里跑）
../tools/newflasher
#    提示 keep userdata? -> n（清空）
#    提示 dump trim area?  -> y（顺手备份 TA，无害）

# 4. 开机后验证补丁级别
adb shell getprop ro.build.version.security_patch   # 必须 < 2016-10
adb shell "mount | grep ' /system '"                # 看是否 dm-0（verity）
```

## 验证通过后的提权

Dirty COW 的 Android run-as 链（timwr/CVE-2016-5195）：

1. `adb install` 一个 debuggable 的测试 APK
2. push `dirtycow` 二进制（arm64）到 `/data/local/tmp`
3. 通过 `run-as <pkg>` 进入，利用 dirtycow 覆写进程内存把 uid 提到 0
4. 得到 root shell 后 `setenforce 0`，部署 su

## 风险提示

- 刷机必然清空 data
- **跨区刷 E6653 固件到 SO-01H**：SIM 锁不会解除，FeliCa / おサイフケータイ 报废，可能影响信号注册
- 未解锁刷官方固件**不影响 TA 分区**，相机 DRM（降噪 / X-Reality）不受影响 —— 这是免解锁方案唯一的额外好处
- 签名不符的固件会在 flash 阶段被拒绝，不会刷成砖
