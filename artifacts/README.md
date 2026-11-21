# artifacts · 设备导出数据

**这个目录不入 git**（`.gitignore` 里整目录排除），原因见
[`../docs/decisions/0009-artifacts-not-in-git.md`](../docs/decisions/0009-artifacts-not-in-git.md)：
TA 含 IMEI 与 DRM keys，分区镜像含机器唯一标识，内核 dump 含完整内存布局。

总计约 105MB。设备若已还原/丢失，这些数据**无法重建**——本地需要异地备份（仍未做）。

## 清单

### `ta/` · TA 分区快照（10MB）

| 文件 | 大小 | 说明 |
|---|---|---|
| `TA.img` | 2MB | 11-11 20:40 快照（含开机日志 A） |
| `ta_verify.img` | 2MB | 11-11 21:18 快照，**单字节写入测试的真实前基线** |
| `ta_after_write.img` | 2MB | 11-11 21:57 写入测试后快照 |
| `backup/TA_snapshot_boot1|2.img` | 2MB×2 | 两次开机的成对快照，`SHA256SUMS.txt` 校验 |
| `win_orig.bin` / `win_mod.bin` | 97B | 单字节实验前后的窗口内容 |
| `security_units.txt` | — | `tad` 拒绝访问的 108 个 unit 清单（uid / size / 偏移 / 内容特征）。**设备派生数据，所以不入库**；重扫方法见 `../docs/guides/device-access.md` |
| `certs/` | — | 从 TA 里剥出的 9 张 DER 证书 + `unit_7da/7d3/851/870.bin` 原始 unit + `sig_851.bin` + `mod_sl.txt`（证书模数） |

**关键事实**：两次开机差 12,686 字节，全在 `0x802–0x806` 日志槽；配置区 1962 个 unit 一字节未变。

### `bootloader/` · 21 个 BL 分区（52MB）

`aboot / alt_aboot / s1sbl / alt_s1sbl / sbl1 / alt_sbl1 / tz / alt_tz / hyp / alt_hyp /
rpm / alt_rpm / pmic / alt_pmic / sdi / alt_sdi / keystore / devinfo / persist / apps_log / config`

其中 `devinfo.img` 与 `keystore.img` **全 0**（本机没有常规解锁标志位）。
`aboot.img` 是 ARM ELF32、基址 `0x3E000000`，逆向主战场。

重建：`scripts/device/bl_dump.sh`（需 root 窗口）。

### `verity/` · dm-verity 探针（3.2MB）

`sys_p1/p10/p20/top/dmend/dmend2/tail2m.bin`（system 分区不同位置的窗口）、
`p44_tail.bin`、`p44_tail1m.bin`（裸分区尾部）、`vf/`（`top.bin`、`l0_0/1.bin`、`l1_0.bin`、
`d5.bin`、`meta8.bin`、`verity_key.raw`）。

用途：`analysis/verity/verify_verity.py` 与 `verify_sig.py` 的输入。当前状态：五级哈希链全部 MATCH；
`verity_key.raw` 的格式仍未解（穷举 0 命中）。

### `device/` · 内核与策略（43MB）

| 路径 | 说明 |
|---|---|
| `partitions/kimg.bin` | 32MB 内核运行时 dump（无 KASLR，含 `cred`/`selinux_enforcing` 定位价值） |
| `partitions/kallsyms.txt` / `.map` | 符号表（5MB×2） |
| `partitions/sepolicy` | **307KB 二进制策略**，`sepolicy_parse.py` 的输入 |
| `partitions/sepolicy_perm` | 策略权限展平结果 |
| `partitions/file_contexts` | 路径→标签映射 |
| `partitions/config.txt` / `config.gz` | 内核 config |
| `partitions/klog_p4.txt` | p4 阶段内核日志 |
| `logs/boot-dmesg.txt` | 开机 dmesg（固定内存布局的证据） |
| `binaries/` | 从设备扒的 `libta.so`、`libmiscta.so`、`taimport`、`ta_param_loader`（bootconfig 语义的字符串来源） |

### `reports/` · 验收与事故记录（7MB）

`accept/`（4 轮验收 `rep_r*.bin`）、`forensics/`（dmesg 前后对照、崩溃标记）、
`shots/`（成功截图、SystemUI 压力测试截图）、`panic_dmesg.log`、`soak_*.log`（三次 soak 稳定性测试）。

### `releases/` · 已构建产物

`Z5-一键root.apk`（25,170B，11-11 版）、`使用说明.md`（随包文档）。

### `firmware/` · 一次失败的固件下载

`dl_headers.txt` + `fw.zip`（2KB，只有错误页）。记录"索尼 API 只给最新版"这条死路。

## 重建顺序（设备在手时）

1. 拿临时 root：`apps/z5root` → 点一下 → 等 `/mnt/su`
2. dump 分区：`scripts/device/bl_dump.sh`
3. dump 内核与策略：`adb shell /mnt/su -c "cat /proc/kallsyms"`、`cat /sys/fs/selinux/policy`、`dd if=/dev/block/bootdevice/by-name/boot`
4. TA 只读验证：`adb forward tcp:19999 localfilesystem:/dev/socket/tad` → `analysis/ta/ta_verify_live.py`
