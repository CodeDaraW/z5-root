# 设备通道手册

设备：SO-01H。

## 0. 基本连线

```bash
adb devices                 # 应有一行显示 device 状态
adb shell getprop ro.build.version.security_patch   # 2017-01-01
adb shell getenforce                                # Enforcing（无 root 时）
```

## 1. 临时 root 窗口

root 不是常驻的。获取方式：装 APK → 点"开始 ROOT" → 等。

```bash
adb install -r apps/z5root/build/signed.apk
adb shell am start -n com.z5.root/.MainActivity   # 或手动点图标
# 15 秒倒计时后 exploit 开始；开机后约 18 秒 /mnt/su 才出现
until adb shell 'test -x /mnt/su' 2>/dev/null; do sleep 3; done
adb shell /mnt/su -c id     # uid=0(root)
```

**窗口特征**：`/mnt/su` 出现 → 可写 TA / 可 dump 分区；重启即消失。

⚠️ 不要 `kill` 名叫 `z5root` 的进程（持着 UAF socket，退出可能 panic 重启）。
⚠️ root 在位期间 SELinux 是 Permissive、`panic_on_oops=0`，别拿这个状态下的行为当"设备默认行为"。

## 2. 只读访问 TA（不需要 root）★

`/dev/socket/tad` 属组 `trimarea`(2993)，`adbd` 在该组内：

```bash
adb forward tcp:19999 localfilesystem:/dev/socket/tad

# 列出可读 unit 的尺寸（示例）
python3 - <<'PY'
from analysis.ta.tadif import Tad
t = Tad(); t.open(1)
for uid in (0x47, 0x52, 0x55, 0x7DA):
    print(hex(uid), t.getsize(uid))
PY

adb forward --remove tcp:19999     # 用完清理
```

- `0x47`→13、`0x52`→4、`0x55`→6 是正常值。
- `0x7DA`/`0x84F`/`0x851` 会返回 `Unit not found(4)`——那是**权限过滤，不代表不存在**。
- 完整被拒清单：`artifacts/ta/security_units.txt`（108 项）。该文件**不入库**（设备派生数据），
  需要时按下面的「重扫被拒 unit」重建。

协议细节与坑见 [`../decisions/0006-tad-as-readonly-channel.md`](../decisions/0006-tad-as-readonly-channel.md)。

### 重扫被拒 unit

清单是**本机 TA 的私有事实**（不同固件不同），所以不入库。要重建就跑：

```bash
adb forward tcp:19999 localfilesystem:/dev/socket/tad
python3 analysis/ta/ta_reject_scan.py          # 默认扫原来那三段区间
adb forward --remove tcp:19999
```

它对每个 uid 发 `getsize`，把非 0 状态的单独列出来，末尾给汇总。判据是「服务端给不给」，
不是「unit 在不在」——状态 4 只说明被过滤。

> 别拿 `ta_scan.py` 干这件事：它只收集「成功且长度非零」的 unit（顺带找 1ACE bootconfig），
> 被拒的那批根本不会出现在它的输出里。
> 清单的「内容特征」列是人工归纳的，只能读自己的 `artifacts/ta/TA.img` 重写。

> ⚠️ 全程只发 `getsize`/`read`，不碰 `write`（op=4）。

## 3. dump BL 分区（需要 root）

```bash
# 脚本在 scripts/device/bl_dump.sh（用 /system/bin/sh 执行）
adb push scripts/device/bl_dump.sh /data/local/tmp/
adb shell /mnt/su -c "sh /data/local/tmp/bl_dump.sh"
adb pull /data/local/tmp/bl artifacts/bootloader/
```

21 个分区、约 54MB。**注意 `TA.img` 含 IMEI/DRM keys，落到 `artifacts/ta/`，不要入库。**

## 4. fastboot 侧的已知响应

```bash
adb reboot bootloader
fastboot getvar all          # 只回 7 个变量，没有 is-unlocked
fastboot oem unlock 0x0000000000000000
# → "Command not allowed"（在解析 code 之前就拒，不是码错）
```

判据：如果哪天它变成 `Incorrect format for unlock data...`，说明 rooting gate 被打开了
（这是比"看状态文本"更干净的观测信号，见 `../pitfalls.md` 第 25 条）。

## 5. 现场取证文件

APK 会把现场写到 `/sdcard/Android/data/com.z5.root/files/prev/`：

```
step.txt out.txt rep.bin att.txt pending.txt meta.txt
```

- `att.txt` 每次尝试的开始/结束；`out.txt` exploit 的 stdout；`rep.bin` 进度标记（定位崩溃点）。
- 日志：`adb logcat -s Z5`

## 6. 收尾检查（每次实验后）

```bash
adb shell getenforce                       # 应回 Enforcing（重启后）
adb shell getprop sys.boot_completed       # 1
adb forward --list                         # 应为空
```
