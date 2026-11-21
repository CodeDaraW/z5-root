# BL 解锁探索 · Review（第三只眼，2026-11-11 晚）

> **📁 路径说明**：文中的 `bl/bl/`、`dump/`、`exploit/probe/` 等旧路径是写作当时的，
> 换算表见 [README.md](README.md)「路径对照」。标题里的文件名见同页「命名对照」。

> 评审对象：`BL-解锁探索.md`（v1，含 §1–§11）与 `BL-导出与分析.md`。
> 评审人只做了**只读/可逆**的操作：源码核对 + 活 root 窗口内 10 分钟判别实验。
> 本文沿用原文的三档可信度标记。

---

## 0. 总评

这份报告的**实验纪律是全系列文档里最好的一份**：可信度分级、对照实验设计
（/cache /data remount 对照、BLKROSET 往返、单字节写入+整盘读回+还原）、
§6.7 对自己实验设计的否定（「重启验证无效」那段自我纠错）都是标准做派。
§8.2 的「TA 备份保的是『还能开机前提下的失误』」是全文最重要、也最容易被
遗忘的一句话。

但它有一个【实测】级结论被我这轮当场**证伪**（第 7 条「mount(2) 整体被拒」），
一个机制归因错了一半（MNT_LOCKED 在这内核里不存在，但 MNT_LOCK_* 锁族真的在起作用），
以及一个**战略层的性价比问题**从头到尾没被讨论（见 §6）。

---

## 1. 我这轮实际做了什么（全部可逆/只读）

### 1.1 内核源码核对【实测】

设备内核：`Linux 3.10.84-perf-gaba44f0 #1 SMP PREEMPT Fri Jan 13 16:56:13 2017 aarch64`
（`kernel-exact/` 里的源码即此内核）。

- `MNT_LOCKED` 这个标志在本内核 **不存在**（`fs/namespace.c` 全文无此符号）。
  报告 §7.2 归因到 `MNT_LOCKED` 的机制名是错的——它是 3.19 才进主线的东西。
- 但本内核 `do_remount()`（namespace.c:1797）有一套 **MNT_LOCK_READONLY /
  NODEV / NOSUID / NOEXEC / ATIME** 检查，全部返回 `-EPERM`；
  且 `copy_mnt_ns` 在跨 user namespace 克隆时会加这些锁（namespace.c:2449-2450、
  831-843）。照源码逻辑，Android 6.0 没有 app user namespace，锁**理论上不会被加上**——
  但见 1.2 的实测：**锁确实被加上了**。源码静态推理在这台内核上不完整
  （可能有厂商 backport 用别的路径设锁），实测为准。

### 1.2 活 root 窗口判别实验【实测】

设备在线、root 窗口存活（`/mnt/su` 可用，getenforce=Permissive，
uid=0 context=u:r:untrusted_app:s0:c512,c768）。在**App 私有挂载命名空间**里：

```
$ mount -t tmpfs none /mnt/t ; mount -o remount /mnt/t
→ 成功（新建挂载 + 自建挂载的 remount 都通）
$ umount /mnt/t
→ 成功

$ mount -o remount /data          （不带标志）
→ mount: Operation not permitted        ← 报告观察到的现象，复现了

$ mount -o remount,rw,nosuid,nodev /data （保留 /data 原有标志）
→ 成功                                  ← 报告没试过的组合
```

**结论【实测】**：`mount(2)` 这个系统调用**没有**「整体失效」。
被拒的精确条件是：**对继承挂载做「不保留现有标志」的 remount**——
`/data` 是 `rw,nosuid,nodev`，裸 `remount,rw` 会把未声明的 nodev/nosuid
从请求标志里剥掉，撞上 `MNT_LOCK_NODEV/NOSUID` 检查（namespace.c:1820/1830）→ EPERM。
把标志带上，同一堵墙立刻消失。

### 1.3 顺手核实的属性【实测】

```
sys.oem_unlock_allowed = 1      （确认，与 BL-导出与分析.md §2.4 一致）
ro.boot.flash.locked  = （空，6.0 该属性未设，无信息量）
dm 设备只有 1 个：dm-0，name=system，uuid 为空（verity 与否未定案，见 §3）
```

---

## 2. 对报告结论表的逐条裁决

| 报告结论 | 裁决 |
|---|---|
| 1. 竞态 root 每次 boot 可用 | 【实测，未动】与本轮窗口观察一致 |
| 2. `oem unlock` 在解析 code 前被拒 | 【实测成立】实验设计好——用**格式正确**的 16 位全零码做探针，把「策略先拒」和「格式错」分开了。但「机型不让走」还不是归因终点，见 §4 |
| 3. TA 未加密、结构已解出 | 【实测成立】 |
| 4. TA 是活动分区（SBL1 写日志） | 【实测成立】这条对「写入能力」的旁证价值被报告正确使用 |
| 5. root 可精确写 TA | 【实测成立】方法学干净（窗口级、单字节、整盘读回、还原） |
| 6. 「改 TA 能力已成立」 | 【推断成立】 |
| **7. mount(2) 在当前 root 环境下整体被拒** | **【证伪】**见 §1.2——不是系统调用被拒，是 remount 的标志集不全。连带 §7.4 的结论「root 天然拿不到挂载命名空间控制权」也要重写，见 §3 |
| （§7.2 的 MNT_LOCKED 机制归因） | 【半错】标志名不存在于本内核；真正的机制是 MNT_LOCK_NODEV/NOSUID 族（且确实生效）。方向对了，名字和引用错了 |

两个小勘误：`getprop` 一次只接受一个参数（多参数会报 usage，原文没踩这个坑但
review 中差点踩）；§6.6 第 1 条「块设备忽略 O_TRUNC」的推断对，但更稳的写法
是 toybox dd 确认过 `skip=`/`seek=` 走 pread/pwrite 路径，无截断风险——实测
整盘读回已覆盖。

---

## 3. 「root 拿不到挂载命名空间控制权」要改写成三条可测的墙

报告 §7 把一堵墙描述成了绝路。实测之后，挡在 `/system` 前面的其实是**三堵
各自独立、各自一条命令能测清的墙**：

1. **MNT_LOCK_READONLY**（大概率有）：继承挂载带 READONLY 锁的话，
   `mount -o remount,rw,seclabel?` 怎么写都会 EPERM（namespace.c:1816-1818，
   保留标志救不了 READONLY，因为请求里 rw 本身就是要清它）。
   一条命令判生死：root 窗口里 `mount -o remount,rw /system; echo $?`。
   只测 EPERM 与否、**不要真写成**（块还是 ro 的，真写挂载态有把 ext4 脏树
   写进 dm 映射的风险）。
2. **块层只读**：dm-0 ro=1 + p44 ro=1。报告 §7.3 已实证 BLKROSET 能清 p44
   （且已还原）。dm-0 的 ro 同样走 BLKROSET。这堵墙是**软的**。
3. **dm-verity**（未知，最关键）：dm-0 name=system、uuid 空、全机只有这一个
   dm 设备——**不能定案**。判别法（root 窗口，一条命令级）：
   - `getprop ro.boot.veritymode partition.system.verified ro.boot.verifiedbootstate`
     （6.0 上各属性存在性不同，哪个有读哪个）；
   - 或读 `/sys/block/dm-0/dm/` 下 sysfs + vold 日志（`logcat -d -s Vold`）。
   verity 若在，「写 /system 字节」整条路线死；verity 若不在（docomo 6.0 +
   dev-keys 指纹的世界里不是没可能），**运行时改 /system 是活的**，
   而且和 BL 解锁无关。

另外补一个报告没提的第四条出口：**setns 直通 init 命名空间**。
3.10 的 `mntns_install` 只要求目标命名空间 user_ns（=init）的 CAP_SYS_ADMIN
+ 调用进程单线程（`fs->users == 1`）。root 进程单线程化后
`setns(open("/proc/1/ns/mnt"), CLONE_NEWNS)` 即可跳进 init 的挂载命名空间，
那里**没有**继承锁。DS 手里有 864 字节级工具链，这是几十行代码的事。
进了 init ns，remount 的对手就只剩上面三堵墙。

> 备注：本轮判别实验我做到 `/data` 为止（原本就是 rw，全组合零数据风险）。
> `/system` 的三个判别命令留给 DS，按「只测 errno、不落写」的纪律跑。

---

## 4. `Command not allowed` 的归因还没收口——有个零成本的候选

报告把它归因到「机型不让走」的抽象策略。但 aboot 自己字符串堆里躺着
一个更具体的候选：`Rooting status is: Not allowed until simlock unlocked`
（0x3E06F182，与 `Rooting override is active` 0x3E06F1D6 同一簇）。

SO-01H 是 docomo 机器，这个年代 docomo 机型出厂带 SIM 锁。**解锁判定链的
第一道门很可能就是 SIM 锁状态**。而这道门有别的出口：

- docomo 2021 年起对老机型提供 **web 页面免费解 SIM 锁**（不需要刷机、
  不需要 root，官方通道）；
- 解 SIM 锁后重跑 `fastboot oem unlock 0x0000000000000000`：
  - 报错**变了**（Incorrect format / 校验失败类）→ 第一道门就是 SIM 锁，
    BL 解锁的主线变成「搞解锁码/签名」，TA 改位降级为备选；
  - 报错**没变** → 「机型级拒绝」坐实，TA 路线才升为主线。

零风险、纯外部操作、一条 fastboot 命令的重试成本。**建议排在所有
aboot 逆向之前做**——它可能直接改写整个战略排序。

静态侧给 DS 一个省一轮试错的方法（对应 §9 未解 #1）：Thumb-2 里字符串引用
走**字面量池**，正确姿势是：
1. 拿到字符串 VMA（已有）；
2. 在镜像里扫 **4 字节小端 = 该 VMA** 的所有命中（这就是池项，DS 说的
   movw/movt 猜测多数情况不需要——Sony aboot 是绝对地址寻址的 ELF）；
3. 对每个池项，扫 PC 相对 LDR：窄 Thumb `01001` 前缀（0x48xx–0x4Fxx）、
   宽 `0xF8DF`、ARM `0xE59Fnxxx`，`目标 = align(PC+4,4)+imm`，命中池项的
   指令位置即引用点；
4. 反汇编引用点周边（capstone thumb 模式）。

---

## 5. 风险模型的两个补强

1. **快照异地化是纸面安全**：两份 TA 快照 + `ta_after_write.img` 全在同一块
   Mac 硬盘上（§8.3 自己点名了却没动作）。2MB 的东西，拷到手机之外的
   任意独立介质（网盘/U 盘）1 分钟。不做，§8 整章是理论安全。
2. **tad 并发**：写裸块设备时 `tad_static` 活着，理论上有和它的写交错
   的竞态（它的写入大多按需、量小，概率低）。写前 `stop tad_static` 或
   至少写后比对 tad 关心区。低成本高保险。

另补一条§6 的边界说明（非否定）：单字节写入验证落在**日志区**，其
「精确落盘」的证明链（sync + 读回一致 + SBL1 独立证明分区可写）对日志区
是闭环的；写到 **unit 区（0x60000 之前）**时，读回一致与 eMMC FTL 真持久
之间还隔着 cache/FTL 一层，sync 的 blkdev flush 一般覆盖它，但这是
「低风险」不是「零风险」——落地改 unit 前值得用一次「写日志区无害字节 →
重启 → 挑一个非 SBL1 覆盖范围的偏移读回」做一次断电穿越（要选 SBL1
不碰的位置才有判别力）。

---

## 6. 战略问题：改 TA 解锁位之前的「期望收益核算」

报告 §9 的「不建议直接改 TA 解锁位」判断正确，但整个 §9 排序里缺一个
前置问题：**BL 解锁的下游价值是什么？** 这台机器——

- root 已在手（每次 boot 18 秒的竞态 root）；
- `/system` 运行时可改与否，就差 §3 的三条命令（若 verity 缺失，不需要 BL 解锁）；
- 若目标是刷自制 boot/system/内核：BL 解锁（或绕过其校验）是必经之路；
- 若目标只是「持久 root + 改系统行为」：§3 的墙全测通的话，根本不用碰 TA。

三条可行主线（TA 改位 / SIM 锁 + 解锁码 / dev-keys 指纹背后的签名线索）
的性价比随目标不同而完全不同。**建议 DS 在投入 aboot 深逆向之前，先回答
「我要 BL 解锁到底是为了什么」**——这个答案决定了哪条主线值得一天以上的投入。

另：`dev-keys` 指纹（§2.5/未解 #5）是这轮唯一没被解释的异常身份信号。
排查方向是外部信息（上一手来源、OTA 历史、是否工程机翻新），它对解锁主线
无直接作用，但可能影响「这台机器的 SIM 锁/保修状态」判断——与 §4 一起看。

---

## 7. 修正后的下一步排序

| 序 | 动作 | 成本 | 风险 |
|---|---|---|---|
| 1 | TA 快照拷出独立介质 | 2 分钟 | 零 |
| 2 | SIM 锁状态确认（docomo web / 拨号码）+ 解锁后重试 `oem unlock` 探针 | 外部操作 + 一条 fastboot | 零 |
| 3 | root 窗口三条判别命令：`remount,rw /system` 只测 errno；`BLKROSET dm-0` 往返；verity 属性/vold 日志 | 10 分钟 | 低（只测不写） |
| 4 | aboot 字面量池 xref（方法见 §4）定位 `Command not allowed` 引用点 | 半天离线 | 零 |
| 5 | 视 2/4 结果决定是否投入 TA unit 映射与改位 | — | 高 |

一句话收尾：**「能不能写 TA」这个问题 DS 已经用教科书级的实验回答完了；
而这轮 review 的真正产出是——通往 /system 的墙其实只有三块砖，其中两块
已经被证明是软的（mount 标志、BLKROSET），第三块（verity）一条命令就能定案。
在动 TA 之前，先花十分钟把 §7 的表格跑完，战略地图可能会整个改变。**

---

## 8. 追加（v2 之后的 round 2）：§9.2 verity 尾部之谜——已完全破译【实测】

DS 在 v2 §9.2 留的问题：「尾部 1MB 找不到 0xb001b001 magic；末 705KB 是
同一个 32 字节『root hash』重复 22,032 次」。本轮用四个探针 + 纯本地计算
把这套布局**完整解出，每一环都有哈希级验证**。

### 8.1 正确的布局【实测】

```
分区 p44 = 1,346,048 块（5,513,412,608 B），dm-0 映射前 1,335,440 块：

[块 0 .. 1,335,439)      数据区（dm-0 映射的就是这段）
[块 1,335,440 .. +8)     verity 元数据区（32 KB）：
   块 1,335,440 开头 = magic 0xb001b001 + u32 0 + ~192B 垃圾/残留
   + 偏移 0x10c 起是明文 verity 表：
     1 /dev/block/bootdevice/by-name/system /dev/block/bootdevice/by-name/system
     4096 4096 1335440 1335448 sha256
     <root hash = a038e4ae…> <salt = aee087a5…>
[块 1,335,448 .. 树尾)    哈希树，root-first（根在最前、L0 在最后）：
   块 1,335,448 = L2 顶块（恰好 82 个非零哈希词）
   之后 82 块 = L1；之后 42,734,080 B = L0（1,335,440 个条目，无块填充）
[树尾 .. 分区尾)          343,552 B 全零（构建器尾部填充）
```

账目精确闭合：32,768（元数据）+ 43,074,048（树）+ 343,552（尾零）
= 43,450,368 = 分区 − dm，**一分不差**。

### 8.2 四个哈希级证据【实测】

1. **`sha256(salt ‖ 4096×00) == 那个重复值 V`**（精确相等）。
   → 重复值**不是 root hash**，是「带盐的零数据块哈希」。
   DS 的 v2 §9.2 把 V 认成 root hash 是误判（root = 表里的 a038e4ae…）。
2. **`sha256(salt ‖ 块1,335,448) == 表里的 root hash`**（精确相等），
   且该块恰好 82 个非零词 = L2 的理论条目数。→ root-first 树布局确认，
   salt 前置的哈希构造确认。
3. 全尾部 2MB 的 32B 词普查：V×54,799 + 零×10,736 + **仅 1 个**其他词
   （0x1488eb000 处的 `eeba8e48…`）。该词位置换算成 L0 条目号恰好是
   **数据块 #1,313,409 = 最后一个非零数据块的哈希**——它之后 22,030 个
   数据块全零。
4. DS 数出的「22,032 次」有精确来历：L0 中从数据块 #1,313,408 到末尾
   恰好 22,032 个条目（1,335,440 − 1,313,408）。这个数字本身就是
   「L0 尾巴覆盖零数据块」的指纹。

### 8.3 对 §9.2 三句话正解

- **为什么找不到 magic**：Android 6.0 的 verity 元数据放在**数据区末尾**
  （块 1,335,440），不是 ChromeOS 式的分区末尾。DS 在尾部 1MB 里找，
  方向就错了——它其实在分区**倒数 43MB 处**。
- **为什么有 705KB 重复**：不是 Sony 变体，是 ext4 尾部 ~215MB 未使用空间
  全零，每个零块哈希成同一个带盐值 → L0 尾部一长串相同条目；
  中间那个唯一不同的词 = 最后一个真实数据块的哈希。
- **为什么尾部还有 343KB 全零**：构建器填充。DS 的两个观察
  （「末 705KB 重复」与「尾部 64KB 全零」）在 v2 里互相矛盾——真相同时
  调和了两者：重复区后面还有 343,552 B 的零。

### 8.4 战略含义（比布局本身重要）

1. **整个 verity 结构（表 + 树）就躺在可写的 /system 分区上**。真正的
   信任锚是：表上的签名 ↔ ramdisk 里的 `/verity_key`（RSA 公钥）→ 而
   ramdisk 在**已签名的 boot 镜像**里。链条清晰：aboot（锁）→ boot.img →
   /verity_key → 表签名 → root hash → 树。这从机制上坐实了 v2 §9.3 的结论：
   持久改 /system 必须过 boot 链，即 BL 解锁（或另找到 dev-keys 签名线索）。
2. **verity 只守护 dm-0 这条路**。root + BLKROSET 清块 ro + 直接
   `mount /dev/block/mmcblk0p44`（自建挂载无 MNT 锁，mount(2) 可用已实证）
   = 运行时绕开 verity 读 /system 原始字节——写也同理（自建挂载 rw remount
   没有锁）。代价：重启后 verity 校验失败（除非改前备份、关机前还原）。
   这是「会话级改 /system」的可行性判据，一条命令可测，属于低成本实验。
3. 给 DS 的复现路径：4 个探针全在 `bl/sys_*.bin`（tail2m / dmend / dmend2 /
   top / p1 / p10 / p20），表、root、salt 都在上面 §8.1 的表里，
   任何人 10 分钟可独立复核。

### 8.5 遗留给 DS 的两个小尾巴

- 元数据区里 magic 与表之间的 ~192B（bf6d56f6… 等）身份未定——像上一次
  写入的残留，也像 Sony 自有字段。不影响模型（表和树已独立验证），
  但如果它真是指向签名块的指针，值得看一眼。
- 块 1,335,441..1,335,447（7 块）里应有 PKCS#7 签名块——本轮只确认了
  非全零、开头为零，没有解 ASN.1。签名算法与 `/verity_key` 的对应关系
  留给 DS（它有完整的 32KB 在 `sys_dmend`/`sys_dmend2` 探针可扩展）。

---

## §9 第四轮复审（2026-11-13，对 v7 结论摘要 + 最小扰动实验的裁决）

> 本轮全部发现来自**只读**分析：aboot 反汇编（复用 DS 的 `arm_dis.py`/`xref_lit.py`，
> 外加全镜像 bl/blx 交叉引用扫描）+ 三个 TA 镜像的本地比对。设备未动。

### 9.1 对 v7 的总评

v7 的自我审计质量是四轮里最高的：把「三件套一起验签」降级为「一起送进后续处理」、
把 §0 从「已定案」降为「高度可疑」、§4-A 用 tad 权威数据三重关闭格式问题——
尤其是主动识别出自己证据链里的循环论证（①的同义反复）并逐条替换成独立证据。
**§7.2 把判据从「找哈希」换成「最小扰动」这个转向，方向完全正确**——
穷举 10,022 组找不到哈希，本来就有第三种解释：签名对象可能是 S1 侧
规范化后的序列化（节点表结构），而不是原始字节的任何连续区间。
静态找哈希是死路，行为实验才是活的判据。

但实验设计本身有四个缺口，其中两个直接影响安全判定和结果解读。
下面按重要度给出本轮的六个新发现。

### 9.2 新发现 R.1：三件套不只 fastboot 读——**每次开机也读**【实测】

DS（以及我上一轮）都默认 `ROOTING_ALLOWED` 只在 `fastboot oem unlock` 时被读取。
错了。全镜像 bl/blx 交叉引用显示，三件套读取函数（`0x3E03C678`）有**两个**调用者：

```
0x3E03C678（读 0x7DA/0x851/0x8B2 → 0x3E0429B0 节点表处理）
  ├── 0x3E03D3CC —— 链1：开机判定路径（v7 漏掉的那条）
  └── 0x3E03E88C —— 链2：fastboot oem unlock 路径（DS 已知）
```

**链1 的身份**（0x3E024A54，经 `{"aboot" → handler}` 服务表 0x3e071ef4 引用）：
- 打印 `'S1 decisions complete, image to boot is %d.'`
- 含 6 路 switch 跳表（`cmp r3,#5; ldrls pc,[pc,r3,lsl#2]`）选启动映像
- 读 TA unit `0x1324` 和 `0x9A9`（后者缺失按缺省——与 DS 的 bootconfig 分析自洽）
- 处理 `0xDEADD00D` 魔数（命中则改写为 `0x21522FF2`，boot image header 的 tamper 类标志）

**含义**：改了 0x7DA 之后，不仅 fastboot 会读到，**下一次开机链1 就会读到**。
这既是风险问题（见 R.2），也是机会（见 R.5）。

### 9.3 新发现 R.2：开机路径对三件套失败是**优雅降级**，不会 brick【实测】

这是「能不能恢复」的决定性证据。链1 内部有**两道**检查、两种失败处理：

| 检查 | 失败路径 | 后果 |
|---|---|---|
| 三件套/rooting 判定（`0x3e03cfd0`） | 打印 `'S1 decisions failed in facility 0x%x with code 0x%x!'` → **跳回正常流程继续**（0x3e024dbc → b 0x3e024b28） | 打印+继续开机 |
| S1 平台固件校验（`0x3e028560`） | 打印 `'S1 platform security configurations failed...'` + `'Failed secuirty configuration deemed too critical to allow boot, shutting down now.'`（secuirty 是 Sony 自己拼错的）+ `'Going down for bootcrash.'` → 关机 | bootcrash |

第二道验的是 **`S1_HexagonSW3 / S1_Video3 / S1_RIVA3 / S1_TZExec3`**（modem/视频/WiFi/TZ
固件映像的签名），**与 0x7DA 完全无关**。也就是说：
**在 0x7DA 明文区改一个字节，不存在「开机判定失败 → 拒绝启动」的路径**。
最坏结果是开机时多打一行 'S1 decisions failed'，然后照常进系统。

### 9.4 新发现 R.3：链2 全流程已解构——实验的观测信号比 DS 设计的更强【实测】

`oem unlock` 处理器（0x3E029834）的完整判定顺序：

```
gate 1  0x3e03e7bc: 读开机时缓存的状态字节
        ├─ *(u8*)0x3e0a9cd5 ≠ 0（Rooting override 激活）→ 放行
        └─ *(u8*)0x3e0a9cf1 == 0（state=Not allowed）→ FAIL "Command not allowed"
        （即：state≠0 或 override 激活，二者其一即过闸）
→ 检查 "already rooted"（打印 'Device is already rooted'）
→ 参数格式检查：需要 "0x%016x"（18 字符）→ FAIL "Incorrect format for unlock data..."
→ 0x3e03e7f8：三件套#2 + unlock code 校验 → FAIL "Command did not succeed"
```

**三个直接推论：**

1. **不需要真的提交解锁码**。如果 `ROOTING_ALLOWED="1"` 生效（state 翻成非 0），
   gate 1 通过，裸 `fastboot oem unlock`（无参数）的响应会从
   `Command not allowed` 变成 `Incorrect format for unlock data. Should be on the form "0x0000000000000000"`。
   **响应文本本身就是判据**——零 wipe 风险（wipe 只发生在校验成功的完整解锁上，
   而 unlock code 我们没有，永远走不到那一步）。比 DS 的「看返回码变不变」信息量大得多。
2. **gate 1 读的是开机时缓存的全局状态字节，不是命令时现读 TA**。
   所以实验协议必须是「写 TA → **重启** → 进 fastboot」——重启这步是硬性的，
   不是隐含的。DS 的计划碰巧满足，但要写死。
3. gate 1 里 override 激活（0x3e0a9cd5≠0）与 state≠0 是**并联**放行。
   这给了 §4-D override 位一个精确定位：它的效果就是在这道闸上绕过 state。
   它的设置点是链1 里 `bl 0x3e04198c` 的返回值（0x3e03d3e4–0x3e03d3f8）——
   **0x3e04198c 验的是什么，是比写 TA 更值得追的静态题**。

### 9.5 新发现 R.4：实验结果解读要修正——「响应变化」不等于「签名不覆盖」【重要】

DS 把实验当成「签名覆盖范围的判别器」，这个框定有一处偏差：
gate 1 用的 state 字节（ctx+0x5C）来自 **kv 解析产物**。如果代码路径是
「先 kv 解析、验签不 gate 状态字节」（或验签只 gate 后面的 unlock code 校验），
那么即使签名覆盖明文，改 '1' 照样翻 gate——响应照样变。

但这其实是**好消息**：实验真正的判别力在「rooting 门开没开」，不在「签名盖不盖」：

- 响应变成 `Incorrect format...` → **rooting 门开了**（无论签名如何）。
  剩下的墙移到第三步：unlock code 校验（docomo 机拿不到合法码）——
  届时真正的问题变成「64 位解锁码能否从签名数据里导出/离线推导」，那是个新题目。
- 响应仍是 `Command not allowed` → 也不能立刻判死「签名覆盖」。
  要先区分两种死因：验签 gate 了状态，还是根本没读到新值。区分办法：
  重启进 Android 后看 aboot 日志有没有 `S1 decisions failed in facility ...`
  （有 = 链1 处理失败，即验签或解析挂了；无 = 读取正常但 state 没翻，
  那才是「签名 gate」的干净证据）。

### 9.6 新发现 R.5：11-11 已经做过一次 TA 单字节写入测试【实测，需要补账】

`bl/` 目录里的三个镜像讲述了当晚（11-11）的故事：

```
TA.img            20:40  原始 dump
ta_verify.img     21:18  复核 dump（与原始差 747 处 = 两次开机间的日志区自然变化）
ta_after_write.img 21:57 写入后 dump
```

`ta_verify` vs `ta_after_write`：**恰好 1 字节差异**——`0x7b001: 0x22('\"') → 0x31('1')`。
该字节属于 **uid 0x804 开机日志槽**（data 偏移 4609，落在
`oemandroidboot.securityflags=0x...` 这段 S1 开机日志文本里）。

三个结论：
1. **TA 写入机制已被实证**：单字节 dd 写入 → 落盘 → dump 验证，全链路通过。
   §7.2 前置条件里的「确认能写回」其实已经有了一半的经验证据。
2. **v7 的「全程零写入」在分区层面不成立**——11-11 晚写过一字节。
   选材很聪明（0x804 是每次开机都会被设备自己重写的日志槽，实际无害），
   但文档的复现链路里缺了这一环，且该字节没有写回记录（大概率已被
   后续开机的日志写入覆盖，但下次 root 会话应顺手 `dd` 读一眼清账）。
3. 0x804 的「每次开机被设备重写」本身就是一条证据：
   **TA 无全分区完整性校验**（否则设备自己就把自己搞挂了）。

### 9.7 对实验的最终裁决

**靠谱，可以点头，但按下面的修正版协议执行：**

| 项 | 裁决 | 依据 |
|---|---|---|
| 单字节等长替换 | ✅ 安全 | 不动记录结构/size/填充；写入机制 11-11 已实证 |
| 开机风险 | ✅ 极低 | 三件套失败=打印+继续（R.2）；critical bootcrash 检查与此 unit 无关；TA 日志区每开机自写证明无全盘校验 |
| 恢复能力 | ✅ 成立 | 前提是 Android 能开机——而 R.2 正是这个前提的证据。恢复 = root → dd 写回（exploit 可重复获取，已多次验证） |
| 最后兜底 | ⚠️ 未核实 | 真砖了（理论上不会）走 Xperia Companion 软件修复——SO-01H 是否受支持需先查，且会丢全部数据 |

**修正版协议**（相对 §7.2 的改动：判据换成响应文本、重启写成硬性步骤、增加恢复能力自证）：

```
前提：Android 正常开机、root exploit 可用、TA.img 备份在手（已有且已验证）
1. root 会话内：ta_parse2 定位 0x7DA 明文中 ROOTING_ALLOWED="0" 的 '0' 字节偏移
   → dd 单字节写 '0'→'1' → dd 读回验证
2. 同一会话内：写回 '0' → 读回验证 → 再写 '1'（这一步是恢复能力的当场自证：
   出任何意外 root 还在手，随时能改回去）
3. 正常重启 → 确认 Android 正常开机（此刻恢复路径已锁定）
4. 进 fastboot（adb reboot bootloader）
5. fastboot oem unlock          ← 无参数，响应文本即判据：
   ├─ "Command not allowed"          → 未生效；回 Android 查 aboot 日志有无
   │                                   'S1 decisions failed' 以区分死因（见 R.4）
   ├─ "Incorrect format for unlock…"  → rooting 门已开（见 R.4 的解读边界）
   └─ 其他文本                        → 按新文本重新解读（全文记录！）
6. 无论结果：重启回 Android → root → dd 写回 '0' → 读回验证 → 清账收工
```

### 9.8 对 v7 其余部分的点评（短）

- **§3 路线表与 §0 降级不一致**：表里「改 0x7DA → 不可行」应标「待定（§7.2-1 实验后定）」，
  否则读者只看表格会拿到过强的结论。
- **§4-A ③ 的「零残留」不是循环论证**：0x84F 的 TLV 顶层消耗数来自 TLV 自身
  length 字段的递归，独立于记录 size 的来源——但真正盖章的是 ⑤（tad 权威比对），
  这个证据等级排序 v7 是对的。
- **E-4（docomo 官方 SIM 解锁）排序应再提前**：链2 的 state 3
  （'Not allowed until simlock unlocked'）与 state 0 是**两道不同的死因**。
  如果本机当前 state 是 3 而不是 0，官方 SIM 解锁可能直接开门，整个写 TA
  实验都可以省掉。做实验时响应文本（如果恰好变化）能顺带区分这一点。
- **下一块静态富矿**：`0x3e04198c`（override 位的设置者，见 R.3-3）。
  如果它验的是某种可触发状态而非熔丝，那是唯一「不写 TA、不碰签名」的路。

一句话收尾：**v7 的方向判断全对，实验可以做；这轮 review 把它从「敢不敢做」
变成了「怎么做才测得准」——判据从返回码换成响应文本、重启写成硬步骤、
增加第 2/3 步的自证环节。而最大的意外收获是 R.1/R.3：三件套在开机
也被读取且失败即降级，这让「能恢复」不再是假设，而是有静态证据支撑的推论。**
