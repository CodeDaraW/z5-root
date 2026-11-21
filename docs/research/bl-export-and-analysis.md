# SO-01H Bootloader 导出与静态分析记录

> **📁 路径说明**：文中的 `bl/bl/`、`dump/`、`exploit/probe/` 等旧路径是写作当时的，
> 换算表见 [README.md](README.md)「路径对照」。标题里的文件名见同页「命名对照」。

日期：2026-11-11
设备：SO-01H / sumire_docomo / MSM8994 / Android 6.0 / 32.1.F.1.98
前提：临时 root（`/mnt/su`，Permissive），全程只读 dump，**未写入任何分区**

> ⚠️ 时效提示：本文是 v1 视角的记录。其中「不能写 `/system`」的归因
> （`mount(2)` 整体被拒 / `MNT_LOCKED`）**已被证伪**，请以
> `BL-解锁探索.md`（v2）§8 为准。本文保留作为过程存档。

---

## 一、已导出分区

`/data/local/tmp/bl/` → 本地 `bl/bl/`，共 21 个，54MB。

| 分区 | 设备节点 | 大小 | 说明 |
|---|---|---|---|
| TA | mmcblk0p1 | 2.0 MB | Trim Area，配置/解锁状态/DRM |
| aboot | mmcblk0p27 | 1.0 MB | 高通 LK，**fastboot 实现** |
| alt_aboot | mmcblk0p28 | 1.0 MB | aboot 备份 |
| s1sbl | mmcblk0p19 | 256 KB | 索尼 S1 二级 bootloader |
| sbl1 | mmcblk0p15 | 1.0 MB | 高通 SBL1（签名块） |
| tz | mmcblk0p23 | 1.0 MB | TrustZone |
| hyp | mmcblk0p11 | 512 KB | Hypervisor |
| devinfo | mmcblk0p35 | 1 KB | **全 0** |
| keystore | mmcblk0p34 | 512 KB | **全 0** |
| persist | mmcblk0p31 | 32 MB | 传感器校准等 |

---

## 二、关键发现

### 2.1 TA 分区没有加密（推翻预期）

熵 1.941 bits/byte，78.4% 为零。2085 条记录，明文。

记录结构（小端）：

```
[magic 0x3BF8E9C1][tag 0x34FFFFFF][payload ...][unit_id u32]
```

- 第一条 tag 不同（`0xFE250348`），应是分区头
- `unit_id` 单调递增：1, 4, 6, 7, 8, 9, 0x0A, 0x18, 0x27 …
- payload 变长，最短记录 20 字节，最长 144 字节
- payload 内含明文 ASCII：`SW_DEFAULT`、`00000000`、docomo APN `#777`、索尼 product code `48994-FAAAANAZQ-00023-00`

**结论：TA 可直接解析，没有整盘加密。** 这是"能不能改"的前提，目前是通的。

### 2.2 aboot 是 ARM ELF，判定逻辑的字符串全在

`elf32-littlearm`，基址 `0x3E000000`，代码段 700 KB。

关键字符串与 VMA：

| 字符串 | VMA |
|---|---|
| `Device is unlocked! Skipping verification...` | 0x3E058F34 |
| `use_signed_kernel=%d, is_unlocked=%d, is_tampered=%d.` | 0x3E05916C |
| `Incorrect format for unlock data. Should be on the form "0x0000000000000000"` | 0x3E05A984 |
| `oem unlock` | 0x3E05AA24 |
| `Rooting status is: Not allowed until simlock unlocked` | 0x3E06F182 |
| `Rooting status is: Done / Not done / Not allowed` | 邻近 |
| **`Rooting override is active`** | 0x3E06F1D6 |
| **`ROOTING_ALLOWED`** | 0x3E0719FF |
| `RCK_HS1/util/src/s1_elf_loader.c` | 邻近 |

`Rooting override is active` 是个值得追的点：aboot 存在一个"覆盖"机制，
能让 rooting 判定被强制改写。如果它的触发条件可控，就不需要 code。

### 2.3 内核 cmdline 暴露了 aboot 的判定结果

```
androidboot.bootloader=s1
oemandroidboot.s1boot=1289-5620_S1_Boot_MSM8994_LA1.2.2_42C
ta_info=1,16,256
oemandroidboot.security=1
oemandroidboot.securityflags=0x00000002
oemandroidboot.aid=4
oemandroidboot.babe08b3=50000000
```

- `securityflags=0x00000002` 最可疑，是 aboot 从 TA 解析后传给内核的状态位
- `ta_info=1,16,256` 对应 aboot 里 `Failed to supply TrimArea info on commandline!`
- `aid=4` 与 TA 中 unit_id=4 的记录存在对应嫌疑（未证实）

### 2.4 设备端其实是"允许解锁"的

```
sys.oem_unlock_allowed = 1
```

结合 `Rooting status is: Not allowed until simlock unlocked` 这句，
`oem_unlock_allowed=1` 说明 simlock 检查这一关是过的。

**卡点不在设备端开关，而在解锁码本身**——索尼不给 docomo 机型签码。

### 2.5 固件是 dev-keys 签名

```
ro.bootimage.build.fingerprint = ...:user/dev-keys
```

不是 `release-keys`。正常零售机应为 release-keys。
这条要么说明是工程/测试固件，要么是 docomo 定制版的签名策略，值得留意
（dev-keys 通常意味着对应的密钥在 AOSP 测试密钥集里，覆盖面比 release 宽）。

---

### 2.6 TA 不是静态分区：每次开机 SBL1 往里面写启动日志

同一台机器两次 dump（开机前后各一次）对比，MD5 不同（摘要值属设备派生数据，不入库）：

```
第 1 次  bl/TA.img
第 2 次  bl/ta_verify.img   （与第 1 次不同）
```

逐字节比对：747 段差异、共 12686 字节，全部落在 `0x60000–0x7d707`。
差异主体是最后 3 条记录（idx 2081/2082/2083），内容是 **SBL1 启动日志**：

```
NEW_VERSION: erased_user_data:true, variant:user, s1boot_version:...
Format: Log Type - Time(microsec) - Message
B -  472384 - SBL1, Start
D -      30 - boot_flash_init, Delta
B -  557906 - PON REASON:PM0:0x2000200a0 PM1:0x200a0
```

结论：
- **TA 约 99.3% 是静态的**（unit 表、DRM keys、校准数据、IMEI），只有尾部
  十几 KB 的日志区每次开机被覆盖，且记录长度可变（导致 magic 偏移整体后移 4 字节）。
- 所以「备份 TA」拿到的是**某一时刻的一致快照**，语义上完全可用于回滚；
  日志区的差异不影响任何 unit 数据。
- 反过来也证明：**boot 链本身就在写这个分区**，它不是一个被硬件锁死的只读区。

## 三、fastboot 判定结果（已取得）

```
$ fastboot getvar all
(bootloader) max-download-size: 0x38600000
(bootloader) security: yes
...共 7 个变量，无 is-unlocked / unlocked
$ fastboot oem device-info     → unknown command
$ fastboot oem unlock 0x0000...0 → Command not allowed
```

- `getvar all` 被裁到 7 个变量，**Sony 刻意不暴露解锁状态**。
- `oem unlock` 有 handler（`oem help` 报 unknown，说明命令表里有它），
  但在**解析 code 之前**就返回 `Command not allowed`：
  区分点是标准实现里格式错应先报 `Incorrect format`，而这里是直接拒。
- 即：门被策略层挡住，不是"码不对"。

## 三·五、TA 的写能力探测（只读）

```
crw------- root root 10,44  /dev/pta              ← Sony 的 TA 字符设备
brwxrwx--- tad  tad  179,1  /dev/block/mmcblk0p1  ← TA 块设备
/sys/class/block/mmcblk0p1/ro = 0                 ← 内核未标记只读
blockdev --getro = 0
getenforce = Permissive
```

`tad_static` 服务在跑，但块设备 `ro=0`，root 下可写。
→ 技术上存在「用户态 dd 整盘写回」的路径，不依赖 fastboot 解锁。

---

## 四、下一步候选

| 优先级 | 动作 | 目的 | 风险 |
|---|---|---|---|
| 1 | 设备恢复 + `fastboot getvar all` | 看 bootloader 自报的解锁状态与能力 | 零 |
| 2 | 追 `Rooting override` 的触发条件 | 可能免 code | 零（静态） |
| 3 | TA unit_id ↔ `ROOTING_ALLOWED` 映射 | 定位解锁位 | 零（静态） |
| 4 | 改 TA 对应 unit | 真正解锁 | **高，可能不可逆** |
