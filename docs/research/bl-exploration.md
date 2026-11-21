# BL 解锁探索（Xperia Z5 / SO-01H）· v2

> **📁 路径说明**：文中的 `bl/bl/`、`dump/`、`exploit/probe/` 等旧路径是写作当时的，
> 换算表见 [README.md](README.md)「路径对照」。标题里的文件名见同页「命名对照」。

> 技术记录，供外部 review。v1 于 2026-11-11 21:00 完成，v2 依据第三方 review 与复核实验重写。
> 所有结论按三档标注，请按标记阅读。

| 标记 | 含义 |
|---|---|
| **【实测】** | 在本机跑过，附命令与原始输出，可复现 |
| **【推断】** | 由实测数据推出，逻辑链可在文内复核 |
| **【未验证】** | 只是假设，尚无证据，不要当结论使用 |

---

## 1. 结论摘要（v2 修订版）

| # | 结论 | 可信度 | v1 状态 |
|---|---|---|---|
| 1 | 未解锁 BL，但可拿到每次开机有效的临时 root（约 18 秒） | 【实测】 | 不变 |
| 2 | `fastboot oem unlock` 在解析 code 之前就被拒（`Command not allowed`） | 【实测】 | 不变 |
| 3 | **拒绝的原因不是 SIM 锁**：`Remote lock is UNLOCKED`，SIM 锁本来就是解开的 | 【实测】 | 新增 |
| 4 | S1 Boot 每次启动都记录 `Rooting status is: Not allowed` | 【实测】 | 新增 |
| 5 | TA 中存有运营商配置 `ROOTING_ALLOWED="0"`（明文 ASCII，NTT DoCoMo 单元） | 【实测】 | 新增 |
| 6 | TA 分区**未加密**，2085 条明文记录 | 【实测】 | 不变 |
| 7 | TA 是活动分区，每次开机 SBL1 往尾部写约 13KB 启动日志 | 【实测】 | 不变 |
| 8 | root 可向 TA 任意偏移写入，**写入精确落盘**（单字节验证） | 【实测】 | 不变 |
| 9 | `/system` 前面是**三堵独立可测的墙**，不是一个「绝路」 | 【实测】 | **v1 结论已被证伪** |
| 10 | **dm-verity 处于启用状态**（`wait,verify` + 验证通过 + dm 设备短 43MB） | 【实测+推断】 | 新增 |
| 11 | 因此「运行时改 /system 就能绕开 BL 解锁」这条设想**不成立** | 【推断】 | 新增 |

一句话：**SIM 锁这条支线可以划掉了；`Command not allowed` 指向的是 TA 里的 `ROOTING_ALLOWED="0"`。**

---

## 2. 修订说明：v1 → v2 改了什么

v1 有一条【实测】级结论是错的，由第三方 review 当场证伪，本轮已复现确认：

| 项 | v1 的说法 | v2 的事实 |
|---|---|---|
| `mount(2)` | 「在当前 root 环境下整体被拒」 | **错**。新建挂载、自建挂载 remount、umount 全部成功；被拒的只是「不保留现有标志的 remount」 |
| 机制归因 | `MNT_LOCKED` | **名字错、方向对**。该内核 3.10.84 无 `MNT_LOCKED` 符号；真正生效的是 `MNT_LOCK_NODEV/NOSUID` 族 |
| `/system` | 「root 天然拿不到挂载命名空间控制权」 | **过度概括**。是三堵独立的墙（§8），其中两堵是软的 |
| SIM 锁（review 提出） | —— | **假设被本地证据否掉**：设备已 `Remote lock is UNLOCKED`（§10） |
| verity（review 提出为「未知」） | —— | **定案：启用**（§9）。review 设想的「若 verity 缺失则运行时改 system 可行」这条乐观分支关闭 |

评价一句：review 用 10 分钟证伪了我一条【实测】，这本身就是 v1 最该被批评的地方——
**我把「三种 remount 都 EPERM」直接外推成了「mount 整体失效」，没有做「新建挂载」这个本该最先做的对照。**
v1 §7.2 还给了它一个听起来很自洽的机制解释，这是更危险的部分：错误结论 + 合理叙事。

---

## 3. 设备基线【实测】

```
型号           SO-01H（Xperia Z5，docomo 版）
系统           Android 6.0 / 32.1.F.1.98
安全补丁        2017-01-01
SoC            MSM8994 (SD810)
内核           Linux 3.10.84-perf-gaba44f0 aarch64
S1 Boot        1289-5620_S1_Boot_MSM8994_LA1.2.2_42C
```

内核命令行：

```
oemandroidboot.s1boot=1289-5620_S1_Boot_MSM8994_LA1.2.2_42C
ta_info=1,16,256
oemandroidboot.security=1
oemandroidboot.securityflags=0x00000002
oemandroidboot.aid=4
```

异常项：固件指纹为 `user/dev-keys` 而非 `release-keys`。【未验证】
结合 §10 的「SIM 锁已解」，这台机器的身份值得再确认（翻新机？工程机？前手已解 SIM 锁）。

---

## 4. 方法：这个 root 到底是什么【实测】

不是 Magisk，是通过 App `com.z5.root` 触发的竞态提权。每次重启要手动启动一次 App，
约 18 秒后 `/mnt/su` 出现，SELinux 标签为 `u:object_r:shell_data_file:s0`。

关键属性决定了后面的所有权限边界：

```
$ /mnt/su -c 'id -Z'
context=u:r:untrusted_app:s0:c512,c768      ← App 域
$ /mnt/su -c 'readlink /proc/self/ns/mnt; readlink /proc/1/ns/mnt'
mnt:[4026536745]   mnt:[4026531840]         ← 与 init 不同的挂载命名空间
$ /mnt/su -c 'grep CapEff /proc/self/status'
CapEff: 00000000ffffffff                    ← 能力集完整，含 CAP_SYS_ADMIN
getenforce = Permissive
```

---

## 5. 实验一：分区导出与 TA 结构【实测】

只读 dump 21 个分区（54MB）到 `bl/bl/`：

```
TA  aboot  alt_aboot  s1sbl  alt_s1sbl  sbl1  alt_sbl1
tz  alt_tz  hyp  alt_hyp  pmic  alt_pmic  rpm  alt_rpm
sdi  alt_sdi  devinfo  keystore  persist  apps_log
```

### 5.1 TA 结构

```
熵 1.94 bits/byte，78% 为零 → 无整体加密
2085 条记录
记录格式：[magic 0x3BF8E9C1][长度/标志][payload 变长][unit_id]
```

### 5.2 TA 不是静态分区

两次 dump 的 MD5 不同。**摘要值属于设备派生数据，仓库里不记录**——要复核就拿自己的
两份 dump 直接比：boot1 ≠ boot2，差异范围与字节数见下。

747 段差异、12,686 字节，全在 `0x60000–0x7d707`，内容是 SBL1 启动日志：

```
B -  472384 - SBL1, Start
B -  557906 - PON REASON:PM0:0x2000200a0 PM1:0x200a0
```

含义：unit 数据占 99.3% 且字节级不变，尾部十几 KB 日志区每次开机重写。
同时独立证明：**boot 链本身就在写这个分区**。

---

## 6. 实验二：fastboot 判定【实测】

```
$ fastboot getvar all              → 仅 7 个变量，无 is-unlocked
$ fastboot oem device-info         → unknown command
$ fastboot oem unlock 0x0000000000000000
FAILED (remote: 'Command not allowed')
```

判读：标准实现在参数格式错时会先报 `Incorrect format`，这里直接 `Command not allowed`，
说明拒绝发生在**解析 code 之前**。v1 把它归因到「机型不让走」这个抽象策略，
v2 在 §10 找到了更具体的东西。

---

## 7. 实验三：TA 写入验证【实测】

目标：`0x7B000`（4096 对齐）处的 4KB 窗口，内容是 kernel log 文本环缓冲。
改 1 字节写回，整盘读回比对，再还原。

```
写前快照  →  写后快照            （摘要变化，值不记录）
diff bytes = 1
  off=0x07B001  old=0x22  new=0x31
读回窗口前 32B: "1000000 oemandroidboot.securit"（原为 "0000000 ..."）
还原后摘要与写前快照一致
```

**只有目标字节变了，其余 2,097,151 字节完全一致。**

两个工程细节：

1. toybox 的 dd 编译时关闭了 `conv=`，`conv=notrunc` 会报错。块设备忽略 `O_TRUNC`，
   直接 `seek=` 不截断（整盘读回已验证）。
2. 写入必须整盘读回比对 SHA256，只比窗口不够。

### 7.1 为什么没做「重启后验证」

日志区每次开机被 SBL1 重写，写标记会被轮转覆盖，重启后读不到无法区分「没落盘」和「被覆盖」。
review 补了一条更准确的做法：要选 **SBL1 不覆盖的偏移**，才具备判别力。这条对
「改 unit 前做一次断电穿越」有效，列为待办。

---

## 8. 实验四：`/system` 的三堵墙（v2 重写）

### 8.1 先纠正 v1 的错误

v1 观察到三种 remount 都是 EPERM，就外推成「`mount(2)` 整体失效」。复现加对照后：

```
[1] mount -t tmpfs none /data/local/tmp/mnttest   → exit 0   ← 新建挂载成功
[2] mount -o remount /data/local/tmp/mnttest      → exit 0   ← 自建挂载 remount 成功
[3] umount /data/local/tmp/mnttest                → exit 0
[A] mount -o remount /data                        → EPERM
[B] mount -o remount,rw,nosuid,nodev /data        → exit 0   ← 同一目标，带上标志就通
[C] mount -o remount /cache                       → EPERM
[D] mount -o remount,rw,nosuid,nodev /cache       → exit 0
```

**`mount(2)` 完全可用。** v1 缺的就是 [1] 这个对照实验。

### 8.2 真正的机制

被拒的精确条件是：**对继承挂载做「不保留现有标志」的 remount**。
`/data` 是 `rw,nosuid,nodev`，裸 `remount,rw` 会把未声明的 `nodev`/`nosuid`
从请求里剥掉，撞上 `MNT_LOCK_NODEV/NOSUID` 检查 → EPERM。把标志带上，墙立刻消失。

【实测】`MNT_LOCK_*` 族确实在生效。
【未验证】`MNT_LOCKED`（v1 引用的那个符号）在本内核不存在——review 核对了
`kernel-exact/fs/namespace.c` 全文。这条我只能引用 review 的源码核对，未自行复算。

### 8.3 `/system` 的三堵墙

```
[E] /system 逐项 remount：
    ro                  → 成功
    ro,seclabel         → 成功
    ro,nosuid,nodev     → 成功
    relatime            → EPERM
    rw                  → EPERM
    rw,nosuid,nodev     → EPERM      ← 保留标志也救不了
```

| 墙 | 状态 | 判别依据 |
|---|---|---|
| 1. `MNT_LOCK_READONLY`（继承挂载的只读锁） | **硬** | 只要请求里带 `rw` 就 EPERM，保留 nosuid/nodev 无效 |
| 2. 块层只读（dm-0 ro=1、p44 ro=1） | **软** | `blockdev --setrw` 对 dm-0 和 p44 **都成功**（已还原 ro=1） |
| 3. dm-verity | **硬**（见 §9） | fstab `wait,verify` + 验证通过 + dm 设备短 43MB |

第 1 堵是最容易被误判成「绝路」的那堵。它挡的不是权限，是**继承挂载的锁属性**，
原则上可以绕（review 提到 `setns` 进 init 命名空间这条出口【未验证】），
但见 §9——绕过它之后还有 verity 在那等着。

---

## 9. 实验五：verity 定案【实测 + 推断】

### 9.1 四条独立证据

```
1. /fstab.qcom:
   /dev/block/bootdevice/by-name/system  /system  ext4  ro,barrier=1,discard  wait,verify
                                                                    ↑ 明确带 verify

2. /verity_key 存在（524 字节，root 可读）
3. partition.system.verified = 1
4. 容量关系：
   system 分区 (p44)  5,513,412,608 B
   dm-0（挂载源）      5,469,962,240 B   = 1,335,440 × 4096
   差额                43,450,368 B     ≈ hash tree + metadata 的量级
```

第 4 条是结构性证据：dm-linear 会把整个分区都映射掉，**只有 verity target 才会
只映射数据区、把 hash tree 留在映射之外**。

### 9.2 布局已解出（v1 的两处「异常」都是找错位置）【实测】

v1 在这里留了两个疑问：尾部找不到 magic、末 705KB 是同一值重复 22,032 次。
两者都在 round 2 解决了，**原因是查找方向错了**——Android 6 的 verity 元数据放在
**数据区终点**，不是分区尾。

实测布局（p44 = 1,346,048 块）：

```
[块 0 .. 1,335,440)         数据区，dm-0 映射的就是这段
[块 1,335,440 .. +8)        元数据保留区 32KB（AOSP VERITY_METADATA_SIZE），只用了第 1 块
[块 1,335,448 .. 1,345,964) 哈希树，root-first：顶层块(1) → L1(82) → L0(10,434)
[块 1,345,964 .. 1,346,048) 尾部填充 83 块 = 339,968 B 全零
```

元数据块 0 的字段（逐字节对得上，非零总长 506 = 0x10c + 238）：

```
0x000  magic 0xb001b001
0x004  version 0
0x008  signature[256]        RSA-2048 原始签名（不是 PKCS#7 容器）
0x108  table_length u32 = 238
0x10c  verity 表 238 字节（明文）
```

表内容与字段：

```
1 <data_dev> <hash_dev> 4096 4096 1335440 1335448 sha256
  root a038e4ae844f7a43…c6eeef
  salt aee087a5be3b9829…e34dfe7
```

**五级哈希链已在本地逐级重算，全部命中**【实测】：

| 级 | 计算 | 结果 |
|---|---|---|
| A | `sha256(salt ‖ 4096×00)` vs 尾部重复值 V | `6eb8c4e1…` MATCH |
| B | `sha256(salt ‖ 顶层块)` vs 表里 root | `a038e4ae…` MATCH |
| C | 顶层条目 0 vs `sha256(salt ‖ L1 块 0)` | `cdc40c62…` MATCH |
| D | L1 条目 0/1 vs `sha256(salt ‖ L0 块 0/1)` | `365fb19a…` MATCH |
| E | L0 条目 5 vs `sha256(salt ‖ 数据块 5)` | `6173e2fd…` MATCH |

所以「末 705KB 重复值」不是 root hash，而是**带盐的零数据块哈希**：ext4 尾部
~96MB 未使用空间全零，每个零块都哈希成同一个 V，L0 尾巴就成了一长串相同条目。

**三处账目修正**（review §8 的数字有偏差，均已用哈希或直读证实）：

| | review §8 | 实测 | 依据 |
|---|---|---|---|
| L0 块数 | 10,433（称"无块填充"） | **10,434** | 1,335,440 = 128×10,433 + **16**，末块有 112 个零词的块内填充 |
| 尾部填充 | 343,552 B | **339,968 B（83 块整）** | 分区块数 − 数据 − 8 − 树 = 83 |
| 唯一异词归属 | 数据块 #1,313,409 | **数据块 #1,310,720** | 直读该块非零、下一块全零，且 `sha256(salt‖该块)=eeba8e48…` 精确相等 |

修正后账目**按块对齐且一分不差**：1,335,440 + 8 + 10,517 = 1,345,965，余 83 块。
尾部 2MB 的 32B 词普查也精确闭合：54,799 个 V（428 整块×128 + 末块 16 − 1 个异词）
+ 10,736 个零（83 块×128 + 末块 112）+ 1 个异词 = 65,536 词。

### 9.4 元数据签名：存在，但没能验通【实测 + 未解】

元数据块里 0x008 处是 **256 字节签名**，不是 review 猜的「7 块 PKCS#7」——
块 1..7 实测**全零**（32KB 保留区只用了 1 块）。这一点 review §8.5 的尾巴判断错了。

我尝试用它验证表签名，**没有成功**：

- `/verity_key` 是 524 字节二进制（`40 00 00 00` 开头，末尾有 `01 00 01` = 65537），
  不是 PEM，也不是标准 DER，结构不像任何公开格式；
- 穷举该文件所有 256 字节窗口作为模数（e=65537 与 3、正序与逆序签名），
  **没有任何一组能解出合法 PKCS#1 v1.5 填充**。

所以：签名字段确实存在，但它的公钥不是这份 `/verity_key` 的直接内容，
可能是 Sony 的封装/混淆格式，由 aboot 或 fs_mgr 解封后再用。

**这不威胁 §9.3 的结论**——真正的问题是「表签名验证是否被跳过」，
而唯一能测的方法是把 `/system` 改掉再启动。那台机器的启动失败**不可现场修**：
`fastboot flash` 被 `Command not allowed` 挡住，只剩 Sony flash mode（绿灯）+ Emma/
Flashtool 刷官方固件可救，但那样改动也被覆盖掉。**实验收益 ≈ 0，风险不小，不值得做。**

### 9.5 对 review 提议的「直挂裸 p44」实验的评估【反对】

review §8.4 建议：root + `BLKROSET` + 直接 `mount /dev/block/mmcblk0p44`
来运行时绕开 verity 读写 `/system`，并称其为「低成本判别实验」。**我认为这条不该做**，
理由不是权限而是文件系统语义：

- `/system` 此刻由 **dm-0** 挂载着 rw，而 p44 是同一份 ext4 数据背后的**另一个 bdev**。
  ext4 用 `s_bdev` 判重，两条 bdev 指向同一份数据时内核**检测不到双挂载**；
  再挂一次 rw 就是两个独立挂载点各自持有脏页和 journal 事务 → 元数据互相覆盖。
  这不是「理论风险」，是 ext4 双挂载的经典后果。
- 只读挂载更安全（`-o ro,noload` 避免回放 journal），**但它什么也证明不了**：
  verity 对读是透传校验，读 p44 与读 dm-0 拿到的是同样的字节。数据块 5 我已经用
  哈希链验证过一致（§9.2 表 E），不需要再挂一次。
- 就算挂通并写成功，收益也只是**会话级**：dm-0 的页缓存不会感知 p44 的改动，
  下次启动 verity 照样失败。而这台机器每次开机都能在 18 秒内重新拿到 root，
  「会话级改 /system」的边际价值极低。

**结论**：这条路径的可行性与价值都被高估了。真正值得投入的仍是 §10.3 的
`ROOTING_ALLOWED`——它决定 BL 解锁是否可能，而 BL 解锁决定能不能**持久**改系统。


### 9.3 结论

【推断】verity 在启用状态，`/system` 的任何字节改动都会在下次启动时验证失败。

**这直接关掉了 review §3 的乐观分支**：review 设想「若 verity 缺失，运行时改 /system
是活的，且与 BL 解锁无关」。实测答案是 verity 在，所以：
要持久修改 `/system`，必须先解决 verity——而这需要能替换 boot 镜像或改 fstab，
两者都回到 BL 解锁（或绕过其校验）这条主线上。

---

## 10. 实验六：SIM 锁与 `ROOTING_ALLOWED`（v2 新增）

### 10.1 review 的假设

review §4 提出：aboot 里有 `Rooting status is: Not allowed until simlock unlocked`，
SO-01H 是 docomo 机，出厂带 SIM 锁，所以 `Command not allowed` 的第一道门可能是 SIM 锁；
并建议走 docomo 官方 web 解 SIM 锁后重试。

### 10.2 设备自己把这个假设否掉了【实测】

TA 里存着 S1 Boot 每次启动的日志，共 3 份（3 次启动），三份内容一致：

```
@0x07a8ff / @0x07bbff / @0x07cf05
  PBA ID: 1292-6804 (4)
  Startup flags: [ONKEY PRESSED] [USB INSERTED]
  Remote lock is UNLOCKED          ← SIM 锁：已解
  Rooting status is: Not allowed   ← rooting：被拒
  [ERROR @ S1/boot/src/s1boot_config_parser.c:595]:
    MiscTA unit 2473 could not be read!
  [ERROR @ S1/boot/src/s1boot_lib_api.c:1503]:
    TA read failed!
  S1 decisions complete, image to boot is ...
```

两点：

1. **`Remote lock is UNLOCKED`** —— 这台机器的 SIM 锁本来就是解开的。
   aboot 里那句 `Not allowed until simlock unlocked` 是**未解 SIM 锁时**的变体文案；
   我们这里报的是不带 simlock 从句的 `Not allowed`，说明 SIM 锁这道门已经过了。
   **docomo web 解锁这条路不需要走。**
2. `Rooting status is: Not allowed` **每次开机都在重复**，是持久状态，不是一次性判定。

### 10.3 找到了一个高度可疑的开关【实测】

TA 中 `0x07877e` 处的一段明文 ASCII（属于 record #2068，范围 `0x786b4–0x78944`）：

```
HOP_ID="608";OP_NAME="NTT DoCoMo";CDA_NR="1299-6036";ROOTING_ALLOWED="0";
CSERVERID="bmcsecs02";AUTHCERT="UNKNOWN";TIMESTAMP="160106 11:31:02"
```

后面紧跟的二进制段里还有 `00101-*`、`44010-*`、`00101-*`——MCC/MNC 白名单，
也就是 SIM 锁那一侧的数据。

**`ROOTING_ALLOWED="0"` 与 `Rooting status is: Not allowed` 在语义上完全对应**，
而且它就在运营商配置单元里，被 docomo 的定制包写成 0。

【推断】这就是 `fastboot oem unlock` 被策略层拒绝的源头。**（§10.5 已用 aboot 反汇编证实）**
【未验证】但有三点必须先解决，才能说「改它就能解锁」：

1. **这个字符串是「活策略」还是「定制历史记录」**？它周围是
   `HOP_ID / OP_NAME / CSERVERID / AUTHCERT / TIMESTAMP` 这类**定制包审计字段**，
   看起来像一份「这台机器被刷了什么定制包」的记录。S1 Boot 可能读另一份活配置。
   这是整个假设最脆弱的一环。
2. **记录有没有完整性校验**？该 record 头部除 magic 外还有 4 个 u32
   （`0x5e3f187f`、`0x2261c9b9`、`0x07d8db25`、`0x15fef59d`），量级像 hash/CRC。
   若 payload 被校验，"0"→"1" 会自动失效。§10.2 里 `MiscTA unit 2473 could not be read`
   那条错误恰好说明：**该校验失败时 S1 Boot 会报错但继续启动**——这是好消息也是坏消息。
3. **unit_id 与 record 的对应关系**没建立，改错位置的风险不可控。

### 10.4 顺带排除

`MiscTA unit 2473` 在本机 TA 里不存在（2085 条记录里没有该 unit）。
它每次都报读不到，但设备正常启动 → 该 unit 是可选项，不是解锁相关。列为噪声。

### 10.5 决定性证据：aboot 真的在读 `ROOTING_ALLOWED`【实测】

§10.3 的第一点疑虑（活策略 vs 审计记录）**已经解决**，方法是交叉引用。

先说一个方法坑：v1 扫 `ldr` 引用时把掩码写成 `w & 0xFFFFF000 == 0xE59F0000`，
这个掩码把 Rd 字段也算进去了，导致除 `ldr r0` 外全部漏掉。正确掩码是
**`w & 0xFFFF0000 == 0xE59F0000`**。修正后两个 bootloader 各命中 1 处：

```
s1sbl.img  字符串 VMA 0x227e6b  池 0x201cfc  引用点 0x201be8  ldr r1,[pc,#268]
aboot.img  字符串 VMA 0x3e0719ff 池 0x3e04a0a8 引用点 0x3e049f9c ldr r1,[pc,#0x104]
```

反汇编 aboot `0x3e049f9c` 起这一段，语义可以直接读出来：

```asm
ldr   r1, [pc, #0x104]   ; r1 = "ROOTING_ALLOWED"
mov   r2, #15            ; 长度 15，正好是该名字的字符数
add   r0, sp, #24
bl    0x3e034b6c         ; 拷名字到栈缓冲
...
bl    0x3e049ce0         ; ★ 按名字取值的解析器
cmp   r0, #0
blt   <返回 0>           ; 取不到 → 不允许
ldrb  r3, [sp, #0xa]     ; 取回值的首字节
cmp   r3, #49            ; '1'
beq   <返回 1>           ; ← 允许
cmp   r3, #50            ; '2'
bne   <返回 0>           ; 其他（含当前的 '0'）→ 不允许
...                      ; '2' 走另一条计数分支（循环上限 4 次）
```

而 `0x3e049ce0` 本身是一个**通用文本解析器**，逐条比对：

```asm
ldrb r3, [r4, r5]
cmp  r3, #61   ; '='  —— 找等号
ldrb r3, [r1, #1]
cmp  r3, #34   ; '"'  —— 找起始引号
...
cmp  r3, #34   ; '"'  —— 找闭合引号
mov  r3, #1
strb r3, [r7]  ; 置"取到了"标志
bl   0x3e0467f0 ; 复制值
```

即它解析的正是 `NAME="value";` 这种格式——**与 TA 里那段
`HOP_ID="608";…;ROOTING_ALLOWED="0";…` 完全同构**。

所以可以确定了三件事：

1. `ROOTING_ALLOWED` **不是审计记录里的一个装饰字段**，aboot 有专门的代码按名字取它；
2. 取值语义：`"1"` = 允许，`"2"` = 另一种模式（带计数分支），其他（含当前的 `"0"`）= 不允许；
3. 解析器吃的是引号包裹的文本值，**当前值 `"0"` 恰好落在"不允许"分支**。

这基本坐实了 §10.3 的推断：`fastboot oem unlock` 的 `Command not allowed` 来自
docomo 定制包写入的 `ROOTING_ALLOWED="0"`。

**但仍有三件事没解，任何一件都能让"改字节"白费甚至变砖：**

| # | 未解 | 后果 |
|---|---|---|
| 1 | record 头部 4 个 u32（`0x5e3f187f`…）是否为完整性校验 | 若是，改完自动失效 |
| 2 | 该文本块是 TA 原文，还是从某个签名容器里解出来的副本 | 若是后者，改 TA 不会改变 aboot 看到的内容 |
| 3 | 改完 `"0"`→`"1"` 后 S1 Boot 是否接受整包 | 不接受 = 起不来 |

第 1 条已做过一轮试探：对整条 record / payload / 去掉头尾等多种跨度，
CRC32、Adler32、MD5 前后 4 字节、SHA1 前后 4 字节、字节和，**全部不匹配**
那 4 个 u32（脚本 `ta_record_probe.py` 可复跑）。这说明要么校验算法非标准
（带密钥的 MAC），要么那 4 个 u32 根本不是校验值。**尚未结论。**


---

## 11. 风险模型与回滚链

### 11.1 可逆性

| 项目 | 能否恢复 | 手段 |
|---|---|---|
| DRM keys / 相机降噪 / X-Reality | 能 | TA 快照写回 |
| 锁状态（relock） | 能 | 同上 |
| boot / system / modem | 能 | 官方 `.ftf` + newflasher |
| **TA 分区写坏** | **不能** | 恢复源就是 TA 自己，无外部副本 |
| SIM 锁 | 不适用（已解） | — |

### 11.2 回滚链

```
能开机 → 拿到临时 root → dd 写回 2MB → sync → 整盘读回比对 SHA256
```

每一环依赖上一环。真正的失败模式：

> TA 被写到 bootloader 拒绝启动 → 拿不到 root → 链条断裂
> → 唯一出口 fastboot → 而 fastboot 拒绝写入
> → 此时才叫真砖。

**TA 备份保的是「还能开机前提下的失误」，不保「开不了机」。**

### 11.3 落地前的硬性前提

1. 固件版本对齐（TA 内含 `fs_version:GENERIC_32.1.F.1.98`）
2. 写回必须一次成功 + 整盘校验
3. 快照要有设备之外的独立副本 —— **目前没有**。两份都在同一块 Mac 硬盘，
   设备 `/data/local/tmp` 另有三份，但会随机器一起没。这是当前最欠的一步。

### 11.4 `tad` 并发

写裸块设备时 `tad_static` 在运行，理论上存在写交错竞态。
低成本做法：写前 `stop tad_static`，或写后比对它关心的区域。

---

## 12. 未解问题（review 重点）

| # | 问题 | 现状 |
|---|---|---|
| 1 | ~~`ROOTING_ALLOWED="0"` 是活策略还是定制审计记录~~ | **已解**（§10.5）：aboot 有代码按名取值，`'1'`=允许、其他=不允许 |
| 2 | TA record 头部那 4 个 u32 是否为完整性校验 | 若是，得先解出算法才能安全改 unit |
| 3 | record ↔ unit_id 的映射 | 未建立，改错位置的直接风险 |
| 4 | ~~verity 元数据布局~~ | **已解**（§9.2）：元数据在数据区终点，非分区尾；五级哈希链已重算验证 |
| 4b | `/verity_key` 的 524 字节封装格式 | 非 PEM/DER，256B 窗口穷举验签全失败；签名的公钥来源未定（§9.4） |
| 5 | `MNT_LOCKED` 是否存在 | v1 引用了不存在的符号；`MNT_LOCK_*` 族已实测生效 |
| 6 | `Rooting override is active` 分支 | aboot 里的另一条路径，触发条件未知 |
| 7 | `dev-keys` 固件指纹 | 来源不明，与「SIM 已解」可能同源 |
| 8 | `setns` 进 init 挂载命名空间 | review 提出的第四出口，未验证；且 §9 之后收益有限 |

### 建议排序（v2）

| 序 | 动作 | 成本 | 风险 | 目的 |
|---|---|---|---|---|
| 1 | ~~确认 `ROOTING_ALLOWED` 是否为活策略~~ | — | — | **已完成**，见 §10.5 |
| 1b | 判定那 4 个 u32 是否为 MAC/校验（换更多算法、看 s1sbl 里同一 record 的读路径） | 半天 | 零 | 决定改字节是否会被拒 |
| 2 | 解 record 头部的校验字段 | 半天 | 零 | 改 unit 的前置 |
| 3 | 一次「断电穿越」写入验证（选 SBL1 不覆盖的偏移） | 30 分钟 | 低 | 把 §7 的证明链补到 unit 区 |
| 4 | aboot 字面量池 xref，定位 `Command not allowed` 的引用点 | 半天 | 零 | 交叉验证 §10.3 的推断 |
| 5 | 视 1/2 结果决定是否改 unit | — | **高** | — |

> 注：aboot 的字面量池扫描方法（review §4 给出）已记录备查：
> 先找 4 字节小端等于字符串 VMA 的池项，再扫 `0x48xx–0x4Fxx` / `0xF8DF` / `0xE59Fnxxx`
> 形式的 PC 相对 LDR，命中即引用点。**v1 直接扫 `ldr` 指令是错的方向。**

---

## 13. 资产清单

```
bl/bl/                 21 个分区镜像，54MB
bl/bl/TA.img           boot1 快照
bl/ta_verify.img       boot2 快照（= 写入验证前）
bl/ta_after_write.img  写入验证后（与写前仅 1 字节差异）
bl/win_orig.bin        验证用 4KB 原始窗口
bl/win_mod.bin         验证用 4KB 修改窗口
bl/p44_tail.bin        system 分区尾部 64KB（全零）
bl/p44_tail1m.bin      system 分区尾部 1MB（verity 树尾）
bl/sys_dmend.bin       元数据区前 16KB（块 0 有内容，其余全零）
bl/sys_tail2m.bin      分区尾部 2MB（词普查用）
bl/vf/meta8.bin        元数据保留区完整 32KB（8 块）
bl/vf/top.bin          顶层块 1,335,448
bl/vf/l1_0.bin         L1 块 0
bl/vf/l0_0.bin         L0 块 0
bl/vf/d5.bin           数据块 5（链末验证用）
bl/vf/db1310720.bin    最后一个非零数据块
bl/vf/verity_key.raw   /verity_key 原始 524 字节
verify_verity.py       verity 五级哈希链复核脚本（可独立重跑）
verify_sig.py          元数据签名验签尝试脚本（结果：未通）
bl/backup/
  TA_snapshot_boot1.img
  TA_snapshot_boot2.img
  （成对快照；校验和见本地 SHA256SUMS.txt，不入库）
  SHA256SUMS.txt
BL-导出与分析.md        前期导出与静态分析（v1 视角，部分结论已被本文替代）
BL-解锁探索.md          本文档（v4）
BL-解锁探索-review.md   第三方 review 原文
ta_parse.py             TA 记录解析器（[magic][标志][payload][uid][x]）
arm_dis.py              ELF32-ARM 反汇编辅助（含字面量池/字符串标注）
xref.py                 字符串与常量的 PC 相对引用回溯
verify_verity.py        verity 五级哈希链复核
ta_record_probe.py      单条记录拆解与校验算法试探
bl/config.img           config 分区 dump（512KB，结论：与配置无关）
```

设备端 `/data/local/tmp/`：`ta_verify.img`、`ta_pre_write.img`、`ta_final.img`。

---

## 14. 第二轮逆向：TA 的存储模型与解锁判定（v4）

这一轮全部是**只读**分析（TA / aboot / s1sbl 的静态数据 + 两次开机快照的差分），
没有写入任何分区。结论对未来是否动手有直接影响。

### 14.1 TA 记录格式（修订 §5）【本节格式已被 §16.1 推翻】

> ⚠️ **勘误**：本节的字段顺序是**反的**。正确布局为
> `[uid][size][magic][flags][data]`，即 `uid`/`size` 位于 `magic` **之前**。
> 按本节写法解析会让每条 unit 的内容整体错位一条。
> 受影响范围：§14.2 的 unit 归属、§15 全章、§10.3 对 `0xA2A` 的定位。
> 保留原文作为取舍痕迹，**引用请一律以 §16 为准**。

实际布局比 v1 描述的更规整：

```
[magic 0x3BF8E9C1][4B 类型/标志][payload…][unit_id u32][x u32]
```

- `unit_id` 在一级区域内**严格递增**（0x1 → 0x907），共 2083 条 magic 记录。
- 4B 标志绝大多数是 `0x34FFFFFF`（1590 条），其余是同族的变体
  （`0x11020202`、`0x14151515`、`0x23232323`…），像是类型/填充标记。
- 说明：v1 里"记录头有 4 个 u32 像校验值"的猜测**不成立**——这 4 字节是标志位，
  不是 MAC。§12 第 2 条可以据此关闭。

### 14.2 哪些 unit 是日志、哪些是配置【实测】

用两次开机快照（`TA_snapshot_boot1/2.img`）做全盘差分，12,686 字节差异只落在 8 个 unit：

| unit | 差异字节 | 性质 |
|---|---|---|
| `0x1046F` | 4550 | 日志 |
| `0x802` | 4458 | 日志 |
| `0x804` | 3655 | 日志 |
| `0x8B3` / `0x1324` / `0xA2B` / `0x803` / `0x806` | 1~14 | 计数/时间戳 |

**结论：`0x802`–`0x806` 是日志槽，每次开机被重写。**

⚠️ 上表是**旧解析器**给出的 uid，整体错位了一条（见 §16.1）。用修正后的解析器重映射，
差异只落在 `0x802 / 0x803 / 0x804 / 0x805 / 0x806`（加 `0x1046F` 的 20 字节、`0x7E5` 的 2 字节），
是**五个连续 uid**——这才符合"一块连续的日志区"的直觉。旧结果散落在
`0xA2A/0xA2B/0x8B3/0x1324`，本身就是串位的症状。

同时纠正：**`ROOTING_ALLOWED` 不在 `0xA2A`**。`0xA2A` 实际只有 4 字节 `1e 00 00 00`，
它确实在两次开机间字节一致，但那是"稳定"而非"装着配置"。真正的所在是 `0x7DA`（§16.3），
且它在差分中同样零变化。

### 14.3 aboot 的解锁/rooting 判定链【实测】

`aboot` 里与 rooting 有关的全部文案（0x3E06F149 起）：

```
Rooting status is: Done
Rooting status is: Not allowed
Rooting status is: Not allowed until simlock unlocked
Rooting status is: Not done
Rooting override is active
```

判定代码在 `0x3E03D3C0`–`0x3E03D520`：先 `bootconfig_open()`，再取 rooting 状态字节，
`2` 或 `5` → "Done"，`0`/`3`/其它 → 三种拒绝文案。状态读不出来时走
"Bootconfig parsing failed! → 请用刷机工具刷入有效 bootconfig"。

而 `0x3E049F04`（v3.1 已定位）从配置对象里按名取 `ROOTING_ALLOWED`，首字节
`'1'`(0x31) → 允许，其它 → 拒绝。`S1_Cust` 这个名字在 `0x3E0409FC` 被引用，
说明配置节是**按名字**查表，不是按 unit id——全盘扫 `movw #0xA2A` 零命中可佐证。

### 14.4 TA 里的 S1 节是带证书链的签名容器【实测】

TA 中扫出 27 张 X.509 证书，其中与 bootloader 相关的 5 张：

| unit | 证书主体 | 签发者 | 算法 |
|---|---|---|---|
| `0x850` | CN=S1_SL | CN=S1_Root_f936 | RSA-2048 / sha256WithRSA |
| `0x870` | CN=S1_RLock | CN=S1_Root_f936 | 同上 |
| `0x805` | CN=S1_HWConf | CN=S1_Root_f936 | 同上 |
| — | CN=S1_GCodes | CN=S1_Root_f936 | 同上 |
| `0x964` | CN=S1_SW | CN=S1_Root_f936 | 同上 |

`0x805` 的 payload 开头是 `53 49 4E`（**SIN**，Sony Image 容器），内部含文本
`cREV="HWC_Kitakami_DOCOMO_Com_010";SERVER="bmcsecs02";AUTHCERT="UNKNOWN";TIMESTAMP=…`
——**和 `0xA2A` 里那段 `HOP_ID=…;ROOTING_ALLOWED="0";…` 是同一种格式**。

也就是说：`ROOTING_ALLOWED` 所在的这块配置，和 S1_SL / S1_RLock / S1_HWConf
属于同一族"运营商定制节"，而这一族在 TA 里是**带证书链与 RSA 签名**的。

另在 `0x62010` 附近还有一张节清单：`[名字][类型][长度][32 字节摘要]`，
列出 `S1_Cust`、`S1_ELabel`、`S1_SL`、`S1_ModemSW`、`S1_FOTA`、`S1_RAMETS`、
`S1_TZExec3`、`S1_RLock`、`S1_GCodes` —— 即 S1 按清单逐节校验。

### 14.5 但有三处对不上，不能直接下"已签名"的结论【未验证】

1. **没有 S1_Cust 的证书**。27 张证书里没有 `CN=S1_Cust`，只有上面 5 个节有。
2. **摘要对不上**。把 `0xA2A` 记录按所有起止组合穷举 SHA-256（含扩展到 0x79000
   的更长范围），没有一个等于清单里 `S1_Cust` 条目的 32 字节值；SHA-1 同样不中。
3. **aboot 实际按 id 读的 unit 大多是空/时间戳**。扫描全部 `read_ta_unit` 调用，
   传入的 id 是 `0x7DA / 0x851 / 0x8B2 / 0x89F / 0x7D3 / 0x84F / 0x8FD / 0x9AF`；
   其中 `0x851 / 0x8B2 / 0x8FD / 0x9AF` 在盘上**不存在**，存在的是时间戳
   （`2016/07/12,12:45:35`、`2021-07-22 00:36:10`）和日志字符串
   （`-9:7:s1sl/s1sl_engine.c:3515`）。

所以更准确的说法是：**`0xA2A` 属于签名节所在的存储区，家族成员都带证书；
但它自己既没有证书、也没匹配上清单摘要，是否被校验仍未定。**

### 14.6 安全结论：现在不该写

即便"未签名"这一支成立，一旦判断错误，失败路径是明确写死的：

```
Bootconfig parsing failed!
Please start your flashing tool and insert the flash cable in order to flash a valid bootconfig.
```

这不是"降级启动"，是**停下来等人刷机**。而当前设备的三条恢复路径都不成立：

| 路径 | 状态 |
|---|---|
| `fastboot flash TA` | 锁着，直接拒（§6 实测） |
| EDL(9008) | 需要 Sony 签名的 firehose programmer，公版被 PBL 拒 |
| Sony flash mode（绿灯）+ newflasher | **未验证**，且需要能构造 `.ta`；本机没有工具链 |

也就是说：`TA` 备份虽然在手，**但没有在"起不来"状态下执行恢复的入口**——
这正是 §11 里那条"保险只保失误、不保变砖"的具体化。写入的期望收益（可能根本
不生效）远小于风险（大概率只能靠刷机工具救）。

**因此本轮结论：停在只读分析。任何对 `0xA2A` 的写入实验，都必须先有一条经过验证的
flash-mode 恢复链路。**

### 14.7 如果还要往下走，顺序应该是

1. **先建恢复链路**（不碰 TA）：确认设备能进 Sony flash mode（绿灯），确认
   newflasher 能识别；用备份构造一份 `.ta`，并**只做 dry-run 校验**。
2. 恢复链路可用后，才做"低语义风险"的写入实验：改 `0xA2A` 段内**填充字节**（不碰
   文本），重启看 S1 是否报 bootconfig 错误——这一步能直接回答"有没有校验"。
3. 只有第 2 步证明无校验，才考虑把 `"0"` 改成 `"1"`。
4. 若证明有校验，则 TA 路线彻底关闭，回到"免解锁 root"的既有方案收尾。

---

## 15. TAD 通道破译：bootconfig 归属与「读不到」的实证（v5）

本节全部为**只读**实验，设备未写入任何字节。目标是回答 §14 遗留的两个问题：
`0x84F` 到底是什么、以及「S1 会不会校验它」。

### 15.1 一句话结论

`bootconfig` 是 TA 里的一个 unit，格式是**二进制 TLV、魔数 `1A CE`**，由 aboot 自己解析；
但它属于 TAD 的**安全 unit**，普通客户端连读都读不到（`Unit not found`）。
主 TA 里挂在该 id 下的内容是**开机时间戳**，不是配置——这解释了 §14 的"对不上"。

### 15.2 aboot 侧：bootconfig 的取用链

反汇编 `aboot`（基址 `0x3e000000`）得到完整链：

```asm
3e03d498  movw  r0, #0x84f          ; unit id
3e03d49c  add   r1, sp, #0x28       ; &buf
3e03d4a0  add   r2, sp, #0x24       ; &len
3e03d4a4  bl    0x3e040350          ; read_ta_unit(id, &buf, &len)
3e03d4a8  subs  r5, r0, #0
3e03d4ac  blt   0x3e03d4c8          ; 读失败
3e03d4b0  ldr   r0, [sp, #0x28]     ; r0 = buf
3e03d4b4  ldr   r1, [sp, #0x24]     ; r1 = len
3e03d4b8  bl    0x3e0476ec          ; parse(buf, len)
3e03d4cc  bge   0x3e03d550          ; 成功 → 继续启动
          ; 失败分支
3e03d4dc  "Bootconfig parsing failed!"
3e03d528  "Will invoke S1 service to obtain a valid bootconfig"
3e03d530  mov   r0, #3              ; 返回码 3
```

参数顺序经 `read_ta_unit` 内部交叉核对确认：`r1 = &buf`、`r2 = &len`，
所以 `bl 0x3e0476ec` 拿到的是 `(buf, len)`，与解析器入口一致。

解析器入口的第一件事就是**魔数比对**：

```asm
3e047700  ldrb  r3, [r5]
3e047704  cmp   r3, #0x1a      ; 第 1 字节必须 0x1A
3e047708  bne   <fail>
3e04770c  ldrb  r3, [r5, #1]
3e047710  cmp   r3, #0xce      ; 第 2 字节必须 0xCE
3e047714  bne   <fail>
3e047744  mov   r0, #0x48      ; 解析结果 = 72 字节结构
```

**即 bootconfig 不是文本，是 `1A CE` 开头的二进制 TLV。**

同时确认 `0x84F` 不是"按 id 读配置"的笔误：`movw r0,#0x84f` 紧邻 `bl read_ta_unit`，
中间没有别的写 `r0` 的指令；`read_ta_unit` 内部把 `r0` 一路传给 `ta_getsize`/`ta_read`。

### 15.3 libmiscta 侧：bootconfig unit 的内部结构

`/system/lib64/libmiscta.so` 的错误字符串直接把结构说清了：

```
'Corrupted bootconfig unit'
'Invalid unit id in bootconfig unit'
'Invalid length in bootconfig unit'
'Invalid startupreason length in bootconfig unit'
'Replacing corrupted bootconfig unit'
```

推论（与 15.2 的 TLV 相互印证）：

| 字段 | 存在性证据 |
|---|---|
| 单元内有 unit id | `Invalid unit id in bootconfig unit` |
| 单元内有 length | `Invalid length in bootconfig unit` |
| 单元内有 startupreason | `Invalid startupreason length in bootconfig unit` |
| 单元可被**重写** | `Replacing corrupted bootconfig unit` |
| 单元可被**写入** | 导出符号 `miscta_write_unit` / `miscta_write_unit_critical` |

**"可重写"这一点很重要**：它说明 bootconfig 在设计上属于**可更新的运行时配置层**，
不是不可变信任根。真正的门槛不在"能不能改"，而在"谁有权限改"（见 15.5）。

### 15.4 TAD 协议破译（不需要 root）

设备上 `/dev/socket/tad` 的属组是 `trimarea`，而 `adbd` 的 `Groups` 里正好含 `2993(trimarea)`，
所以经 `adb forward ... localfilesystem:/dev/socket/tad` 即可直连。协议从 `libta.so` 反汇编得到：

```
请求（全大端）: [u32 len+9] [u8 ver] [u32 a0] [u32 op] [payload ...]
  ver = 1
  op  = 0 open   payload = [mode, 1]
  op  = 2 getsize payload = [u32 unit]
  op  = 3 read    payload = [u32 unit]
  op  = 4 write   payload = [u32 unit][u32 len][data]

回包: [u32 total] [body]
  getsize body = [u32 status] [u32 size]    （失败时只有 status）
  read    body = [u32 status] [u32 len] [data]
```

`status`: `0=Success`、`4=Unit not found`、`5=Operation not allowed`、`6=Trimarea not valid`。
`ta_open` 的正确调用是 `(mode, 1, 1)`，`mode=1` 才返回 `Success`（`mode=0` 返回 6）。

工具已落盘为 `tadif.py`（只读封装）。

> 过程记录：最初把 `ver` 写成 0、把 `op` 与 `a0` 位置搞反，`tad` 回 `Request format error [457]`；
> 另有两次因"按固定长度读回包"导致流错位，把 `getsize` 的 size 误读成后续字段——**早期那版"扫描无结果"不可信，已重做**。

### 15.5 实测：普通 unit 可读，安全 unit 被过滤

`mode=1` 下逐个查询：

| unit | 结果 |
|---|---|
| `0x0047` | `Success`，13 字节，内容 `"SW_DEFAULT\0\0\0"` |
| `0x0052` | `Success`，4 字节，内容 `"0000"` |
| `0x0555` / `0x0027` 等 | `Success`，长度与 TA dump 的记录尾字段一致 |
| **`0x084F`** | **Unit not found** |
| **`0x0851` / `0x08B2` / `0x08FD` / `0x089F` / `0x07DA`** | **Unit not found** |
| **`0x0A2A` / `0x09BB` / `0x0964`** | **Unit not found** |

即：**aboot 会读的那几个 unit，在客户端视图里全部不存在**。
这不是"数据为空"，而是 `tad` 在服务端做了可见性过滤——普通 unit 正常返回长度和内容，
安全 unit 直接报 `Unit not found`。

旁证：`/system/bin/ta_param_loader` 只支持 `prox_cal` / `threshold` / `rfilter` 三个固定参数，
正是因为它只能碰普通 unit；官方工具本身就没打算暴露配置层。

### 15.6 ~~修正 §14 的解释：`0x84F` 是时间戳，且失败是"软失败"~~【整节作废，见 §16.2】

> ❌ **本节结论错误，已作废。** `0x84F` **不是**时间戳，它是一份**完全合法的
> `1ACE` bootconfig（97 字节）**。本节之所以读出时间戳，是因为 §14.1 的字段顺序反了，
> 读到的是**相邻** unit 的内容。因此"设备在没有有效 bootconfig 的状态下启动"这个结论
> 也不成立——它一直正常解析、正常启动。§16.2 给出了逐字段解码。

作为记录，保留当时的推理链如下（**均不要再引用**）：

```
"2016/07/12,12:45:35" + 0x00 填充 + 0x2323 对齐   ← 这是 0x84F 的"邻居"，不是 0x84F
```

### 15.7 对解锁路径的意义（v6 重写）

| 路径 | 状态 |
|---|---|
| 从 Android 侧**读** bootconfig（`0x84F`） | **封死**：`tad` 对客户端隐藏该 unit，返回 `Unit not found` |
| 从 Android 侧**写** bootconfig | 同上，预期封死；未实测，不做 |
| 改 `ROOTING_ALLOWED` | **不在 `0xA2A`**，在 `0x7DA`（§16.3）；且 `0x7DA` 被 SIN 签名覆盖（§16.4） |
| 直接写块设备 | 需 root；但即便写进 `0x7DA`，签名一变即失效 |

**净结论（v6）：TA 路线不是"权限封住"这么简单，而是"权限 + 密码学"双重封闭。**
无 root 时读不到；有 root 时能写，但写进去的 `ROOTING_ALLOWED` 会被 SIN 校验判为无效，
因为签名用 Sony 私钥（`CN=S1_Root_f936` 签发，RSA-2048/SHA-256），我们造不出来。

> 注：`0x84F` bootconfig 本身**没有**出现在 SIN 校验路径里（§16.2 的 type-2 只是引用其它
> unit）。所以"改 bootconfig"在密码学上比"改 `0x7DA`"宽松——但它里面**根本没有**
> rooting 相关字段，改它只会改启动触发器。这条区分很重要，避免再一次把两件事混为一谈。

另一个降低风险的事实：libmiscta 有 `Replacing corrupted bootconfig unit` 的自愈逻辑，
说明 bootconfig 损坏在**Android 启动之后**可被修复——但这救不了"aboot 阶段就停住"的情况。

### 15.8 复现清单

```bash
adb forward tcp:19999 localfilesystem:/dev/socket/tad
python3 tadif.py            # 打开 mode=1，查 unit 0x84F
adb forward --remove tcp:19999
```

产物：`tadif.py`（客户端）、`ta_scan.py`（批量扫描）、`ta_tools/`（libta.so、libmiscta.so、
ta_param_loader、taimport 等，用于离线反汇编）。

### 15.9 下一轮建议（均需先确认恢复链路）

1. **只读**：`ta_write` 对一个**无关紧要且可重建**的普通 unit 做写入/回滚测试，
   确认 op=4 的权限边界——**这一步有写入行为，必须先批准**。
2. 若确认普通 unit 可写，再看安全 unit 是否返回 `Operation not allowed`（而不是 `Unit not found`），
   这能区分"权限过滤"与"根本不存在"。
3. 无论结果如何，**在此之前不碰 `0x84F`**。

## 16. 记录格式勘误与 rooting 判定链定案（v6）

本轮**全程离线**：只读 TA dump + 反汇编 aboot，**没有对设备发出任何写命令**，
连 `tad` 的写接口（op=4）都没有调用过。

### 16.1 勘误：TA 记录格式（推翻 §14.1）

正确布局是 **uid/size 在前**：

```
[uid u32][size u32][magic 0x3BF8E9C1][flags u32][data (size 字节)][填充到 4 字节边界]
```

三条短记录逐字节验证（`size` 与 `tad` 返回的权威尺寸完全一致）：

| uid | size | 数据区 |
|---|---|---|
| `0x47` | 13 | `"SW_DEFAULT"` + 3×`0x00` |
| `0x52` | 4 | `"0000"` |
| `0x55` | 6 | `"000000"` |

**当初为什么读反**：填充字节取自 `flags` 的高 3 字节（常见 `0xFF` / `0x15` / `0x23`），
于是"数据 + 填充 + 下一条的 uid/size"在视觉上像"数据 + 尾部 uid/size + 重复的 flags"。
把 magic 当记录起点、向后找两个 u32 当尾部，就正好错位一条。

修正后的自检：

- 2082 条记录，`uid` 基本递增；
- 两次开机差分（12,686 字节）只落在 `0x802`–`0x806` 这**五个连续 uid** 上 —— 自洽；
- 旧解析器给出的散点分布（`0xA2A/0xA2B/0x8B3/0x1324`）就是错位的症状。

新解析器：`ta_parse2.py`（`records()` 返回 `uid/size/off/mark/data_off/data`）。

### 16.2 `0x84F` 的完整解码：它是一份合法的 1ACE bootconfig

`0x84F` = 97 字节，以 `1A CE 28 00` 开头。条目格式（由 `s1boot_config_parser.c` 反汇编还原）：

```
条目 = [u16 LE size][u8 type][u8 subtype][size-2 字节 payload]
       size 从 type 字节起算 → 整条目占 2+size 字节
```

顶层 6 条，**恰好消耗 97 字节、零残留**，这是格式判对的最强证据：

| 偏移 | type | size | 含义 |
|---|---|---|---|
| `0x02` | 1 | 40 | 启动触发器表（嵌套） |
| `0x2C` | 2 | 18 | unit 引用表 |
| `0x40` | 3 | 4 | 未知（2 字节） |
| `0x46` | 4 | 4 | 未知（`b0 04`） |
| `0x4C` | 6 | 14 | 未知（12 字节） |
| `0x5C` | 9 | 3 | 未知（1 字节 `01`） |

**type 1 的载荷**是 `[u8 count][count 个条目]`，本例 `count=6`，六个触发器：

```
03 00 02 04 02              → subtype 4 = USB OTG   (要求 size=3)
05 00 02 02 0e 00 10        → subtype 2 = GPIO      (要求 size=5)
05 00 01 03 02 00 10        → subtype 3 = GPIO      (要求 size=5)
05 00 03 03 03 00 10        → subtype 3 = GPIO      (要求 size=5)
05 00 05 83 02 00 10        → subtype 0x83→3 = GPIO (要求 size=5)
02 00 05 85                 → subtype 0x85→5 = PowerKey (要求 size=2)
```

（subtype 的 `0x80` 位被 `& 0x7F` 剥掉后不参与分派；长度校验来自
`Keypad trigger of invalid size` / `GPIO trigger` / `USB OTG trigger` / `Power-key trigger`
四组断言，本例六条**全部通过**。）

**type 2 的载荷**是若干组 `[u32 标记][u32 unit]`，aboot 会拿第二字段当 unit id
**递归** `read_ta_unit` 继续解析：

```
0xBABE09A9 / 0x000009A9   → 继续读 unit 0x09A9
0xBABE08B3 / 0x000008B3   → 继续读 unit 0x08B3
```

`0x8B3` 在盘上存在（4 字节 `50 00 00 00`），`0x9A9` **不存在**（读失败按缺省处理）。

**结论：bootconfig 只描述"开机触发器 + 引用其它 unit"，里面没有任何 rooting 字段。**
它也不是 SIN 校验的对象——所以在密码学层面它比 `0x7DA` 宽松，但改它换不到解锁。

### 16.3 `ROOTING_ALLOWED` 的真正位置：unit `0x7DA`

```
unit 0x7DA, 639 字节
  [0x000..0x08C]  141B 高熵区（SIN 容器头/签名材料）
  [0x08D..]       HOP_ID="608";OP_NAME="NTT DoCoMo";CDA_NR="1299-6036";
                  ROOTING_ALLOWED="0";\0
                  CSERVERID="bmcsecs02";AUTHCERT="UNKNOWN";TIMESTAMP="160106 11:31:02"\0
  ...             6 个以 02 00 xx 0A 起始的分块，含 IMEI 明文
```

aboot 在 `0x3E03C6CC` 处 `read_ta_unit(0x7DA)`，读进来的就是这个 buffer。

### 16.4 它是被 SIN 签名覆盖的

同一个函数里紧接着读证书：

```
0x3E03C6CC  read_ta_unit(0x7DA)  → 配置
0x3E03C6E4  read_ta_unit(0x851)  → 证书
0x3E03C714  read_ta_unit(0x8B2)  → 可选（本机不存在）
0x3E03C794  bl 0x3E0429B0        → 校验
```

`0x851` 里是完整 DER 证书，`openssl` 解出：

| 单元 | subject | issuer | 算法 | 有效期 |
|---|---|---|---|---|
| `0x851` | `CN=S1_SL` | `CN=S1_Root_f936` | RSA-2048 / sha256WithRSA | 2014-06-13 ~ 2034-06-15 |
| `0x7D3` | `CN=S1_HWConf` | `CN=S1_Root_f936` | RSA-2048 / sha256WithRSA | 2014-03-26 ~ 2034-03-28 |

`0x7D3` 的数据头正是 `03 53 49 4E 00`（`\x03SIN\0`），是 HW 配置的 SIN 容器。
aboot 里还有 `secmgr_verify_sin_header` / `secmgr_verify_sin_end` 两条文案，确认校验由 secmgr 执行。

**`SL` 即 SimLock。** 这与字符串 `Rooting status is: Not allowed until simlock unlocked`
完全自洽：**运营商的 SIM 锁配置和"是否允许解锁 BL"被签在同一份 blob 里。**

### 16.5 rooting 状态机（伪代码）

```
0x3E03D3C0:  SIN 校验(0x7DA, 0x851[, 0x8B2])        → 0x3E03C678
0x3E042B30:  先 try_parse(ROOTING_ALLOWED)          → 0x3E049F04
             再读状态字节                            → 0x3E04A330
0x3E04A330:  *out = *(u8*)([ctx + 0x5C])            ← 状态就存在这个字节
0x3E03D3C0:  switch(state) 与文案的对应关系
                2 或 5 → "Rooting status is: Done"
                0      → "Rooting status is: Not allowed"
                3      → "Rooting status is: Not allowed until simlock unlocked"
                其它   → "Rooting status is: Not done"
0x3E03D450:  if override 标志 ≠ 0 → "Rooting override is active"
0x3E044AE0:  override = *(u16*)([ctx + 0x58] + 0x1C) & 0x2000
0x3E03D468:  0x3E043040 / 0x3E0430C4 → 写 2/1/0 供 fastboot 使用
```

两点值得记下：

1. **override 不是配置文件里的开关**，而是某个运行时对象的 16 位状态的第 `0x2000` 位。
   它更像硬件/引导模式的标志，"Rooting override is active" 是诊断态而非用户可写项。
2. 状态字节存在 ctx 的 `+0x5C`，来源是 SIN 校验那条链——**不是**从 bootconfig 读的。

> 置信度说明：`state` 与 `ROOTING_ALLOWED` 取值的**逐值映射**（"0"→state 0/3）
> 目前是"函数相邻 + 语义自洽"的强推断，还差一步动态验证才能称为实测。
> 但**"`0x7DA` 被 SIN 签名覆盖"这一点是实测**（证书解出来了、调用链闭合）。

### 16.6 三条路线的可行性重排

| 路线 | 密码学门槛 | 权限门槛 | 变砖风险 | 判定 |
|---|---|---|---|---|
| 改 `0x7DA` 的 `ROOTING_ALLOWED` | **需 Sony RSA-2048 私钥** | 需 root | 中 | **不可行** |
| 改 `0x84F` bootconfig | 无签名覆盖 | 需 root | 中 | 无收益（不含 rooting 字段） |
| 伪造 SIM 解锁状态 | 同一份签名 | 需 root | 高 | **不可行** |
| 触发硬件 override 位 | 可能绕过签名 | 需物理条件未知 | 低（只读判定） | **唯一还有想象空间的方向** |
| Android 侧漏洞提权 | — | 已有临时 root | 低 | 只解决"能写 TA"，不解决"写了算数" |

**关键认知转变**：之前几轮把"能不能写进 TA"当成了主问题。今晚证明，
**即使写得进去也不算数**——rooting 判定的输入是签名保护的。所以"拿到 root → 改 TA → 解锁"
这条路是断的，不必再为它准备恢复链路了。

### 16.7 复现清单（全部离线）

```bash
python3 ta_parse2.py bl/bl/TA.img          # 修正后的记录解析，自带 uid/size 自检
python3 -c "..."                            # 导出 unit 0x84F / 0x7DA 至 .bin
python3 bootcfg_decode.py bootcfg_84f.bin   # 1ACE 容器递归解码
openssl x509 -inform DER -in cert_851_0.der -noout -subject -issuer -text
```

产物：`ta_parse2.py`、`bootcfg_decode.py`、`bootcfg_84f.bin`、`unit_7da.bin`、
`cert_851_0.der`、`cert_7d3_0.der`。

### 16.8 实验：签名可以离线验证，但"被签消息"的封装还没复现

本轮唯一没有走完的一条线，但已经把问题压缩成一个非常具体、可复现的形式。

先把 SIN 容器的大致骨架定下来（`0x870`、`0x7D3` 两个带 `\x03SIN\0` 魔数的单元）：

```
0x870: 1155 − 131  = 1024
0x7D3: 2351 − 1327 = 1024
```

两个都差出**整 1024 字节**，那就是签名块（4×256，Sony 惯用的冗余签名）。

`0x851` 虽然没有 SIN 魔数，但结构同样整齐：

```
[20B 头][691B 证书 CN=S1_SL][3B: 02 01 00][256B 签名]
20+691+3+256 = 970 = 单元全长   ← 严丝合缝
```

拿 `0x851` 里的证书公钥做 `sig^65537 mod n`，得到**完全合法的 PKCS#1 v1.5**：

```
00 01 FF×202 00 ‖ 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 <32B>
```

`60 86 48 01 65 03 04 02 01` = SHA-256。**这是一枚真签名**
（随机 256 字节凑出合法填充 + 合法 OID 的概率可忽略）。被签的是 **32 字节摘要**，
值不记录——它是这台设备 TA 内容的摘要，属设备派生数据。

**还没确定的是：这个哈希对应哪段字节。** 已排除：

| 尝试 | 结果 |
|---|---|
| `0x7DA` 的全部连续子区间（639×639 穷举） | 无命中 |
| 全盘 2082 个 unit 的整块 / 去头 8·16·20·24B / 去尾 256·1024B | 无命中（10,022 组） |
| `uid+size` 大小端前缀 + 数据 | 无命中 |
| `0x7DA` 与 `0x851`（含/不含证书、含/不含签名）的拼接 | 无命中 |
| 双层 SHA-256 | 无命中 |

**判断：被签消息不是任何 unit 的直接字节，而是规范化/多段拼接结构**
（SIN 容器典型的"头 ‖ 证书摘要 ‖ 内容"形式）。要闭合这一条，需要把 `0x3E0429B0`
里 hash 上下文的 update 序列读懂——纯静态、零风险，是下一轮的第一件事。

**为什么这一条重要**：它直接决定"改 `0x7DA` 到底有没有用"。

- 若签名覆盖包含明文配置段 → 改了就废，TA 路线彻底封死；
- 若只覆盖前 141 字节、明文在覆盖范围外 → **那是一条真路**。

在这一点没有结论之前，任何"写 `0x7DA`"的尝试都是拿设备赌博。**不做。**

### 16.9 下一步（都不碰设备）

1. **读懂 `0x3E0429B0` 的 hash 序列**，复现"被签消息"的封装 —— 决定 `0x7DA` 能否被改，
   这是当前唯一的关键未知量（见 §16.8）。
2. 反过来查 `0x8B2`：本机没有这个 unit，但 aboot 会尝试读。确认它是"可选签名"还是"必需"。
3. 评估硬件 override 位的来源（`[ctx+0x58]+0x1C` 这个对象是谁、0x2000 位由谁置）。
4. 以上任何一步若指向"可在 Android 侧达成"，再讨论恢复链路；**在此之前不动设备**。

### 16.10 设备在线复验：记录格式全量通过，`0x3E0429B0` 的角色需要更正（v7）

2026-11-13 深夜设备重新连上（`SO-01H` / `6.0`），补上了 v6 遗留的第一号缺口。

**（a）全量比对通过**【实测】

`ta_verify_live.py`：对 dump 里 2070 个不同 uid 逐个问 `tad`：

| 项 | 数量 |
|---|---|
| 设备可读并比对 | 1962 |
| 尺寸一致 | 1962（100%） |
| 内容逐字节相同 | 1962（100%） |
| 尺寸或内容不一致 | **0** |
| 设备拒绝 `Unit not found(4)` | 108 |

`ta_uid_scan.py` 扫 `0x0000-0x1500` / `0x2700-0x2800` / `0x10400-0x10500`：
**没有"设备有、dump 无"的可读 unit**。所以 §16.1 的格式不仅没错位，也没有漏记录。

> 踩坑记录：首次跑报 9 处尺寸不一致，全在日志区。原因是同一 uid 在配置区和日志区
> **各有一次记录**，我取了 `[-1]`（日志区），而设备返回的是配置区那份。改成配置区优先后归零。
> 这是"取错记录"，不是"格式判断错"——但这个坑值得记，因为日志区的副本尺寸确实不同
> （例如 `0x132C`：配置区 1 字节计数器，日志区 9 字节 ASCII `"1295-0130"`）。

**（b）108 个拒绝单元 = 权限，不是缺失**【实测】

清单见 `security_units.txt`。里面除了 `0x7DA`（rooting 配置）、`0x851`（`S1_SL` 证书）、
`0x84F`（bootconfig），还有 `MARLIN` / `MARLIN_IMPORT` / `WIDEVINE` / `DTLA` / `CKB`
这些 **DRM provisioning** 单元（`0x7E6` 25330 字节、`0x7E8` 37778 字节）。
DRM 密钥和解锁配置在同一张拒绝表里 → 这是统一的"机密区"策略。

`open()` 的 `mode` 取 0/1/2 结果完全一致，说明门在策略层不在打开方式。

**副作用（重要）**：`tad` 对机密区回的是 `Unit not found`，而不是 `Operation not allowed`。
**"不存在"和"不给你看"在这个接口上是同一个返回码**。任何基于 `tad` 的存在性探测
都会把机密 unit 误判为"本机没有"——`0x8B2` 到底是不存在还是被挡，用这个接口**无法区分**。

**（c）`0x3E0429B0` 不是哈希验签，§16.8 的描述要改**【实测】

沿 `0x3E03C67C`（读 `0x7DA`→`0x851`→尝试 `0x8B2`，然后把三件套 + 上下文交给
`0x3E0429B0`）往里读，发现它的三个被调目标全是**节点表操作**：

| 地址 | 行为 |
|---|---|
| `0x3E0449B8` | 统计链表中 `id == r0` 的节点个数 → `*r1`（u8） |
| `0x3E044A00` | 找第 `r1` 个 `id == r0` 的节点，`node[+2]`（u16）→ `*r2` |
| `0x3E044A60` | 同定位，从 `node[+4]` memcpy `r3` 字节 |

节点 = `{u16 id, u16 len, void *data, node *next}`，表头在文档对象 `+0x18`。
**这是"在已解析结构上按键取值"，不是"往哈希上下文里 update"。**

同时 `0x3E049F04` 被确认是**通用 kv 查找**（先 `memcpy("ROOTING_ALLOWED",15)` 做 key，
再在内存"文件"里查值），不是"ROOTING_ALLOWED 专用解析器"。

含义：aboot 侧"读 rooting 状态"和"处理签名容器"是两段独立代码，
v6 把它们写在一条链上（§16.8 的"送进去验签"），**这个说法不准确，本版更正**。
真正的哈希如果存在，很可能不在 aboot 里算。

**（d）`0x851` 的头里出现了 `0x07DA`**【实测，弱证据】

`0x851[0:20]` = `02 00 09 07 DA 27 0F 00 15 02 1C 00 03 BC 00 01 02 B5 02 B3`

另外两个相邻的安全 unit 是**标准 SIN 容器**（头 `03 "SIN"`，大端 u32：`0x400 / 条目数 / 2 / 0 / 0x24`）：

```
0x870: 03 53 49 4e | 00000400 | 00000029 | 00000002 | 00000000 | 00000024 | 00000083 ...
0x7D3: 03 53 49 4e | 00000400 | 00000022 | 00000002 | 00000000 | 00000024 | 0000052f ...
```

两者在证书前都有同构收尾 `... 00 00 03 C0 | 00 01 | 02 B9 | 02 B7 | 30 82 ...`，
而 `0x851` 是 `... 00 03 BC | 00 01 | 02 B5 | 02 B3 | 30 82 ...`，且
`0x3C0 - 0x2B7 = 0x3BC - 0x2B3 = 265`。`0x2B7/0x2B3` 正好是该 DER 证书的总长。

**所以 `0x851` 不是 SIN 容器，但它的头用了同一套"证书长度"收尾编码，且显式写着 `0x07DA`。**
这对"配置段被签名覆盖"是**方向一致**的证据，但两字节也可能是巧合，**不作为实证**。

**（e）本轮对结论的影响**

没有翻转，但把不确定性集中到了一个点上：
记录格式这条现在可以放心标【实测】（三重独立证据）；而"签名覆盖什么"仍然只能靠**动态最小扰动实验**判定，
静态这条路我判断代价过高且未必有解（哈希可能根本不在 aboot）。

### 16.11 回应外部 review：两个调用者、开机写 TA、以及"零写入"的更正（v8）

外部 review 指出三件套"不只 fastboot 读，开机也读"。核实结果：**成立，是我漏了。**

**（a）三件套函数有两个调用者**【实测】

入口是 `0x3E03C678`（不是我一直用的 `0x3E03C794`——那只是其中一个调用点）：

| 调用点 | 参数 | 上下文 |
|---|---|---|
| `0x3E03D3CC` | `(0, 0)` | 紧邻 `Will invoke S1 service to obtain a valid remote lock data object`；返回后立刻 `bl 0x3E04198C` |
| `0x3E03E88C` | `(r5, 0x10)` | 开机判定路径，随后写 TA（见 b） |

R2 参数含义因此清楚了：`r0/r1` 是**外部提供的可选 blob 及其长度**，
非零时替代 `0x8B2` 的位置（对应 §16.x 里 `[sp+0x24]=r0 / [sp+0x18]=r1` 那段）。
fastboot 侧不提供（0,0）→ 走读 `0x8B2`；开机侧提供 16 字节 → 走外部 blob。

**（b）aboot 在开机路径里自己写 TA**【实测，重要】

```
0x3E03E8F4  ta_size(0x8B2)  → 为 0 则跳过
0x3E03E908  ta_clear(0x8B2)           ; 0x3E045F2C
0x3E03E918  ta_write(0x8B2, r5, 0x10) ; 0x3E045B10
0x3E03E930  ta_write(0x9F6, &2, 1)
```

`0x3E045B10` 内部先检查全局标志字节 `[0x3E0A9D50]`：`[+2]` 为 0 → `Trimarea not valid(6)`，
`[+0] & 6` 为 0 → `Operation not allowed(5)`，然后按 unit 查节点、比对长度、必要时创建。

**两个推论**：
1. **TA 写入是引导器日常动作**，不是危险操作 → "写 TA 必然 brick"的担心可以放下。
2. **`0x8B2` 不是"本机不该有的可选件"**，而是开机刷新的 16 字节缓存。
   旧结论"本机不存在"撤回，改为"按分支创建/清除"。

**（c）更正"全程零写入"**【实测】

`bl/ta_after_write.img`（11-11 21:57）与 `bl/bl/TA.img`（20:40）差 12,686 字节。
按记录归类后，差异**全部**落在 `0x7E5 / 0x802 / 0x803 / 0x804 / 0x805 / 0x806 / 0x1046F`
＋记录外 14 字节——**恰好是 `tad` 拒绝的那批日志/机密槽**，配置区 1962 个 unit 一字节未动。

其中 `0x7b001` 处 `0x30('0') → 0x31('1')`，**单字节写入测试确有其事**。
该偏移落在 `uid 0x803` 的数据区间 `0x79E00–0x7B0EC`（review 说 `0x804`，差一位；
`0x804` 从 `0x7C3F0` 起）。

⚠️ 方法论教训：**整盘 md5 或"两份 dump 只差一字节"这种验证方式在这里失效**，
因为 log churn 的 12,686 字节会把单字节信号淹掉。
我上一版之所以只敢写"一字节未改"，就是被这个现象误导——**看起来"没变"其实是有变化但没法归因**。

**（d）没核实的部分**

review 说"开机路径失败是优雅降级（打印后继续）"、"真正 bootcrash 的是另一道
验 modem/视频/WiFi/TZ 的检查"。字符串 `S1 decisions failed in facility ...` 确实存在，
但"失败后继续启动"这个控制流我**没有逐步走完**，暂列【强推断】。


## 17. 变更记录

| 时间 | 版本 | 内容 |
|---|---|---|
| 2026-11-11 21:00 | v1 | 初稿：导出、写入验证、/system 归因（含错误结论） |
| 2026-11-11 22:00 | — | 第三方 review 证伪 §7「mount(2) 整体被拒」，提出 SIM 锁假设 |
| 2026-11-11 22:20 | v2 | 复现并确认 review 的证伪；重写 §8 为三堵墙；verity 定案；SIM 锁假设被本地证据否掉；新发现 `ROOTING_ALLOWED="0"` |
| 2026-11-11 23:55 | v3 | §9.2 改写为「已解出」：元数据位置、五级哈希链逐级重算、修正 review 的三处账目与「7 块 PKCS#7」误判；新增 §9.4 签名存在但验签未通 |
| 2026-11-12 00:10 | v3.1 | 新增 §10.5：aboot 反汇编证实 `ROOTING_ALLOWED` 是活策略（`'1'`=允许）；记录 LDR 掩码踩坑；新增 §9.5 反对「直挂裸 p44」实验 |
| 2026-11-12 00:40 | v4 | 新增 §14：修订 TA 记录格式；用两次开机差分区分日志 unit 与配置 unit；定位 aboot 的 rooting 判定与 bootconfig 装载链；证实 TA 内的 S1 节带 S1_Root_f936 证书链（RSA-2048/SHA-256）；给出「无验证恢复链路前禁止写入」的安全结论 |
| 2026-11-12 01:20 | v5 | 新增 §15：破译 TAD 协议（`ver=1` / `op=0,2,3,4`，大端），打通**无需 root** 的 TA 读取通道；实测确认 `tad` 对客户端过滤安全 unit，而普通 unit 可正常查询；据 aboot 反汇编定案 bootconfig 为 `1A CE` 二进制 TLV；结论：TA 路线在无 root 的 Android 侧已被服务端权限封死 |
| 2026-11-12 01:15 | v6 | **勘误 + 定案**。①推翻 §14.1：TA 记录格式应为 `[uid][size][magic][flags][data]`，旧版把首尾读反、整体错位一条，§14.2/§15 的 unit 归属全部随之作废；用差分重映射自洽（差异收敛到连续 `0x802`–`0x806`）验证修正正确。②`0x84F` 实为 **97 字节合法 1ACE bootconfig**，逐字段解码（type1 六条启动触发器、type2 递归引用 `0x9A9`/`0x8B3`），推翻了 §15.6「设备以默认配置启动」的结论。③`ROOTING_ALLOWED="0"` 真正位于 **unit `0x7DA`**（非 `0xA2A`），与 `OP_NAME="NTT DoCoMo"`、`CDA_NR`、`HOP_ID`、IMEI 同处一份运营商配置。④该 unit 与 `0x851`（证书 `CN=S1_SL`，签发者 `CN=S1_Root_f936`，RSA-2048/SHA-256）绑定并送 `0x3E0429B0` 校验，字符串侧证 `secmgr_verify_sin_header/end`。⑤给出 rooting 状态机伪代码（state 存于 `ctx+0x5C`，override 取 `[ctx+0x58]+0x1C` 的 `0x2000` 位）。**净结论转向：即便拿到 root 能写 TA，改 `0x7DA` 也过不了签名——"拿 root → 改 TA → 解锁"这条路是断的，不必再为它准备恢复链路。** ⑥新增 §16.8：用 `0x851` 内证书公钥对尾部 256 字节做离线 RSA 验签，解出合法 PKCS#1/SHA-256 DigestInfo，证实签名真实存在；但被签消息的封装尚未复现（639×639 子区间穷举 + 全盘 10,022 组形态均未命中），这是当前唯一的关键未知量。全程零写入 |
| 2026-11-13 23:20 | v7 | **设备在线复验 + 角色更正**。①补上 v6 第一号缺口：用 `tad` 权威 size/内容对 1962 个可读 unit 全量比对，**尺寸与内容 100% 逐字节一致、零差异**；补扫 uid 空间确认无漏记录，记录格式升为【实测】。②证实 `tad` 的 108 个拒绝单元是**权限不是缺失**（名单含 MARLIN / WIDEVINE / DTLA / CKB 等 DRM provisioning，与 `0x7DA` 同在拒答表内），`mode` 0/1/2 无差别；副作用是「不存在」与「不给你看」返回同一码，`0x8B2` 的存在性用该接口无法判定。③**更正 v6 对 `0x3E0429B0` 的描述**：其三个被调目标是节点表查表（`{u16 id, u16 len, void* data, node* next}` 的按 id 计数 / 取值 / 取数据），不是 hash update；`0x3E049F04` 是通用 kv 查找而非 rooting 专用解析器，故「三件套送进去验签」的说法不准确。④新发现 `0x851` 的 20 字节头含 `0x07DA`；`0x7D3` / `0x870` 是标准 SIN 容器而 `0x851` 不是，但共用「证书长度」收尾编码——方向一致的弱证据，不作实证。⑤结论未翻转，不确定性收敛到「签名覆盖范围」一点，判定手段改为动态最小扰动实验（需用户明确同意，默认不做）。全程零写入 |
| 2026-11-13 23:45 | v8 | **回应外部 review**。①采纳并更正：三件套函数入口是 `0x3E03C678`，有**两个**调用者（fastboot `0x3E03D3CC` + **开机判定 `0x3E03E88C`**），此前只找到一个，§16.x 的前提「只在 fastboot 读」作废。②**新证据：aboot 在开机路径里自己写 TA**（`0x3E03E8F4`：size→clear→write 16B 到 `0x8B2`，再写 1B 到 `0x9F6`），故「写 TA 必然 brick」的担心可放下；顺带撤回「`0x8B2` 本机不存在」，改为开机按分支创建/清除的缓存。③更正「全程零写入」：`bl/ta_after_write.img` 确实存在，与 `TA.img` 差 12,686 字节，但**全部是两次开机之间的日志轮转**（落在 `tad` 拒绝的 `0x7E5/0x802-0x806/0x1046F`）；真实写入是 `0x22→0x31`（非 review 说的 `0x30→0x31`，后者误把旧快照当写前基线），且已还原；该偏移在 `uid 0x803` 而非 `0x804`。④`0x3E04198C` 读到的是 `tst #0x1000`（非 `0x2000`），"override 设置者"定位不足，待追。⑤未核实：开机失败是否优雅降级，字符串存在但控制流未走完，列【强推断】 |
| 2026-11-14 00:0x | v9 | **写入风险评估（为「改 0x7DA 一个字节」决策准备）**。①目标定位精确到字节：`0x7DA` 数据区 file `0x0786BC`、639B，`ROOTING_ALLOWED="0"` 的 `'0'` 在 **file `0x07878F`**，全盘唯一一处，等长替换不动 size/magic/mark/padding。②结构视图：该 unit 是 TLV 容器（16B 高熵前缀 + `[4B tag][1B 0x0A][32B]` 重复 9 次 + 143-284 明文配置段 + IMEI 明文），改动点落在明文段内、不碰任何边界。③穷举 `639×639/2` 组子区间 SHA-256/SHA-1 比对全部 32B 块，**0 命中** → 那些块不是自哈希，只能是 HMAC 或外部摘要，**不可重算**。④结构损坏风险判极低：unit 头无 hash、分区头 12B 无全局 hash、尾部无 hash 块；且 aboot 自己每次开机都写 TA（§16.11）。⑤**恢复路径重新评估**：fastboot 在 BL 锁定时不给 flash（第 2 层不成立）；Xperia Companion **不重写 TA**（TA 含 IMEI/DRM keys，不在 FTF 包内）——审阅方说的这层兜底我认为不成立；实际只有「能启动 → root → dd 写回」这一层。⑥指出 §7.1 的缺口：11-11 那次写入**没重启过**，故「写 TA 后重启正常」至今无直接证据；建议加「原样写回 + 重启穿越」作为前置闸。⑦新增静态线索：`0x3E049F04`（kv 查 `ROOTING_ALLOWED`）只被 `0x3E042B30` 调用，且是纯文本查找**不验签**；`0x3E03C678` 只调内部 12 个子块，未直接 bl 外部 crypto → 「先静态定位验签输入范围」应优先于写实验。全程仍零写入 |
| 2026-11-14 00:2x | v10 | **官方解锁路径代码级还原（用户提出的新方向）**。①证书身份实测：`0x1046C` = `CN=S1_RLock`（Remote Lock）、`0x7D3` = `CN=S1_HWConf`、`0x851` = `CN=S1_SL`，三者同为 `03 "SIN"` 且由 `CN=S1_Root_f936` 签发；`0x7D3` 是分区描述表，条目含 `S1_RLock` 与 **`S1_GCodes`**（Sony 解锁码体系，本机为空）。②`fastboot oem unlock` 控制流读出：`0x3E03D3CC` 三件套 → `0x3E04198C` 定 override → 状态 2/5 = Done → `ta_clear(0x1046B)` → `0x3E043040`/`0x3E0430C4` 定状态；另一分支打印 `Will invoke S1 service to obtain a valid remote lock data object`，成功后 `ta_write(0x1046C, …)` + `ta_clear(0x8BA)`。③**判据收敛到一张 16 位位图**：`[ctx+0x58]+0x1C`，**bit 1 (`0x2`)** = rooting 允许（`0x3E043040`），**bit 12 (`0x1000`)** = override（`0x3E04198C`）；override 只影响一行日志、不改控制流。④未查完：该位图由谁填充、源头是 TA 还是熔丝——这是「有戏/没戏」的唯一分界。⑤诚实结论：方向比「改 ROOTING_ALLOWED」更有结构（代码是被产品验证过的），但终点未必是 BL 解锁，可能只是把墙从 A 挪到 B。全程零写入 |
| 2026-11-14 00:55 | v11 | **收费工具路线追到底**。①**设备端解析路径完全不验签**（硬证据）：`0x3E043A54` 解析 SIN 容器只做魔数 `0x03 "SIN"` + 长度/字段边界，末尾证书只存进节点不校验；`0x3E040D7C` 读字节映射 0-5；`0x3E049F04`/`0x3E049CE0` 是纯文本 kv 匹配。②**真正的门是「外部 S1 服务句柄」**：`0x3E042458`/`0x3E0425AC` 开头都检查 `ctx+0x44`，为 0 直接失败；处理记录用 `blx [r5+0x2c]` 回调插件函数。三条字符串坐实 S1 服务=外部刷机工具。③完整流程还原：`oem unlock 0x<16hex>` → 写 0x1046B 请求 → 重启由 S1 服务验 code → 通过则写 0x1046C+清 0x8BA → 再启动读 0x7D3 建组件表 → 查 `S1_RLock` bit0 → `0x3E043040` 判表头 +0x1C 的 bit1 → Done。**code 验证不在 aboot**。④结论修正：「改明文可行」**推翻**（那是显示层），「设备端验签」**否定**（信任被外包），未知量从「签名范围」变为「S1 服务验证什么」。⑤收费工具卖的是**签名能力**，不是绕过——瓶颈是钥匙不是逆向。⑥降级分支 `ctx+1==1` 全区间扫描只找到清零、无写 1，判为**死代码**。全程零写入 |
