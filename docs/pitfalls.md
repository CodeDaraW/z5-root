# 踩坑清单

按"症状 → 根因 → 正确做法"三段写。**动手前扫一遍，能省一天。**
每条后面标注了代价（时间/事故）和出处。

---

## 一、TA / 固件逆向

### 1. TA 记录格式读反，所有 unit 内容错位一条

- **症状**：解析出来的每条 unit 内容和预期差一位；填充字节像是"payload 尾部字段"。
- **根因**：真实布局是 `[uid u32][size u32][magic 0x3BF8E9C1][flags u32][data][4B 对齐填充]`，
  **uid/size 在 magic 之前**。v4 把 magic 当记录头、把 uid/size 当尾部，于是每条整体偏移一条。
  填充字节取自 `flags` 的**低字节**（常见 `0xFF/0x15/0x23/0x13`），这也是"看起来像字段"的诱因。
- **正确做法**：用 `tad` 服务的权威尺寸做外部校验——`0x47`→13B `"SW_DEFAULT"`、
  `0x52`→4B `"0000"`、`0x55`→6B `"000000"`。**解析器的自检不能自证**（见第 6 条）。
- **代价**：污染此前所有"某 unit 里是什么"的判断，结论整体回滚重做。
- 出处：`research/bl-exploration.md` §16.1，脚本 `analysis/ta/ta_parse2.py`

### 2. PC 相对 LDR 的掩码写错，扫出来全是零

- **症状**：扫 aboot 里"谁引用了这个字符串"，结果 0 命中。
- **根因**：ARM `ldr Rd,[pc,#imm]` 的编码是 `0xE59Fxxxx`，其中低 12 位是立即数、**bit12-15 是 Rd**。
  用 `0xFFFFF000` 做掩码会把 Rd 也算进去 → 全漏。
- **正确做法**：`(w & 0xFFFF0000) == 0xE59F0000`。
- **代价**：一轮实验白跑（v1 就栽在这）。
- 出处：`analysis/aboot/xref.py`、`xref_rooting.py`

### 3. `bl` 编码判定顺手排掉 0xE，误伤条件执行

- **症状**：全镜像交叉引用扫描漏掉大量调用点。
- **根因**：`bl` 的判定写成"`(w & 0x0F000000) == 0x0B000000` 且 `(w>>28) != 0xF`"是对的；
  但另一版写成排除 `0xE`，而 `0xE` 正是 `cond=AL`（无条件）——
  正确写法是**只排除 `0xF`**（那是 BLX 寄存器/SVC 那条编码空间）。
- **正确做法**：`(w & 0x0F000000)==0x0B000000 and (w>>28)!=0xF`。
- 出处：`history/工作日志.md`（11-13 深夜）

### 4. verity 元数据"找不到 magic"，是因为找错了位置

- **症状**：在分区尾部 1MB 里找不到 `0xb001b001`，于是判"元数据异常"。
- **根因**：Android 6 的 verity 布局里 magic 在**数据区末尾块**（本例块 1,335,440），
  不是 ChromeOS 那种"分区最尾部"。同块 `0x10c` 处还有明文 verity 表。
- **正确做法**：先算 `hash_start_block`，从 `hash_start_block*4096` 往前找；
  尾部 705KB 的重复值也**不是 root hash**，而是 `sha256(salt‖4096×00)`（带盐零块哈希），
  那是 L0 的尾段（ext4 尾部 ~215MB 全零）。
- 出处：`research/bl-review.md` §8，复核脚本 `analysis/verity/verify_verity.py`

### 5. 拿隔了一次重启的镜像当"写入前基线"

- **症状**：单字节写入实验的"改前值"被判成 `0x30('0')`，但设备读回是 `0x22`。
- **根因**：`bl/bl/TA.img`（20:40）与写入测试（21:57）之间**隔了一次重启**，
  而该偏移落在开机日志槽（uid `0x803`），日志已被轮转覆盖。真正的写前基线是 `ta_verify.img`（21:18）。
- **正确做法**：任何"改前/改后"比对，基线必须在**同一次开机内**取得，且确认目标偏移不在日志槽。
- **代价**：一度把"12,686 字节的日志变化"错算到实验头上，结论表述出错又修正一次。
- 出处：`research/bl-conclusions.md` §6.1

### 6. 用"数据必然自洽"的等式证明格式正确（循环论证）

- **症状**：`data_off + size + 填充 == 下一条起点` 在 2082 条里 2080 条成立，看着像强证据。
- **根因**：解析器本身就是**按 `size` 跳到下一条**的，这个等式**必然成立**。
  它只能证明"magic 没在数据区乱出现"，**不能**证明 `size` 字段读对了。
- **正确做法**：内容层零残留才是证据——`0x84F` 的 6 条 TLV 恰好耗完 97B、
  `0x851` 的 `20+691+3+256=970` 且 DER 可解析、`0x7DA` 明文恰好止于 639B 的 `\0`。
  以及外部权威尺寸（`tad` 的 getsize）。
- 出处：`research/bl-conclusions.md` §4-A

### 7. 把"显示层"当成"判定层"

- **症状**：在 TA 里找到明文 `ROOTING_ALLOWED="0"`，以为改成 `"1"` 就能解锁。
- **根因**：这只是**状态显示**。真正的判定在 `0x3E043040`，读的是 S1 组件表头 `+0x1C` 的 **bit1**；
  而且 `0x7DA` 整段被 `0x851` 的 RSA-2048 签名覆盖。
- **正确做法**：判定链要一路追到"谁做最终 if"，不要停在"谁打印这行字"。
- 出处：`research/bl-conclusions.md` §10、§11

### 8. 把"只在 fastboot 读"当既定前提

- **症状**：基于"三件套只在 fastboot 解锁时读"设计了整套实验与风险评估。
- **根因**：三件套函数（入口 `0x3E03C678`）有**两个调用者**，另一个是**开机判定路径**
  `0x3E03E88C`——每次开机都读。前提作废，风险评估随之改变（单字节扰动其实不会 brick）。
- **正确做法**：在反汇编里对目标函数做**全调用点搜索**（`bl`/`movw+movt`/服务表数据指针三管齐下），
  而不是找到一个调用点就收手。
- 出处：`research/bl-review.md` §9.2

### 9. `tad` 返回 `Unit not found` 不等于"这个 unit 不存在"

- **症状**：`0x8B2` 用 `tad` 读不到，判"本机不存在"。
- **根因**：`tad` 对安全 unit 做**可见性过滤**，机密 unit 返回的是 `Unit not found(4)`
  而非 `Operation not allowed(5)`，两者在客户端无法区分。108 个被拒 unit 里含
  `0x7DA/0x851/0x84F` 与 MARLIN/WIDEVINE/DTLA 等 DRM provisioning。
- **正确做法**：判"存在与否"只能用**分区级 dump**（有 root 时）或反汇编证据
  （例如 aboot 开机路径会 `ta_write(0x8B2, 16)`，说明它是按分支创建/清除的缓存）。
- 出处：`research/bl-conclusions.md` §7.1，`artifacts/ta/security_units.txt`

### 10. TAD 固定长度读回包 → 流错位

- **症状**：早期"扫描无结果"，且后续字段被误读成 size。
- **根因**：`getsize` 的回包 body 长度**随状态变化**（失败时只有 status，没有 size 字段）。
  按固定长度 `recv` 会把下一个回包的字节吃进来。
- **正确做法**：严格按 `total` 驱动解析：先读 4 字节 `total`，再读满 `total` 字节。
  另外 `ver` 必须填 1（填 0 得 `Request format error [457]`），`open` 的 `mode` 必须为 1。
- 出处：`analysis/ta/tadif.py`（客户端已按此实现）

### 11. 单字节写入测试选在"会被开机重写"的日志槽

- **症状**：写入验证"能写、能落盘、能读回"全通过，但重启后无法判别。
- **根因**：选中的偏移在 uid `0x803` 的开机日志槽，每次开机被 SBL1 覆盖。
- **正确做法**：可判别性要求目标偏移**跨重启稳定**。日志槽只能验证写入机制，不能验证持久性。
- 出处：`research/bl-conclusions.md` §6.1、§7.1

---

## 二、内核提权 / SELinux

### 12. 动 `security_load_policy()` 前没读完它的分支 → sidtab 重建

- **症状**：清 `ss_initialized` 再回灌策略后，relabel 补丁失效、SystemUI 崩溃循环、
  一度误诊为"相机硬件坏了"。
- **根因**：`security_load_policy()` 有两条分支，其中一条会**重建 sidtab**，
  把所有已分配的 SID 打乱——依赖 SID 的 relabel 链条全部失效。
- **正确做法**：把"奇技"当地基之前，读完它调用的**所有**函数源码，**尤其是分支结构**。
  单条路径读通不等于函数读通。
- **代价**：probe70~77 十几个小时 + 一串事故。
- 出处：`research/root-retrospective.md` §A.2 弯路①

### 13. `struct cred` 的 keyring 区（0x50~0x68）写脏了 → `key_get()` 野指针 oops

- **症状**：`setresuid`/`setgroups`/`fork` 一律 panic，`dmesg` 只有 `panic_on_oops` 复位。
- **根因**（**踩过两次**）：
  - 第一次：写 `0x74` 的副作用落到 `0x60 thread_keyring` → 野指针（probe107~111 九连崩）。
  - 第二次：第 3 写 `0x58 ← 1` 造锚点，第 6 写的副作用 `0x5c ← 1` 让
    `process_keyring = (1<<32)|1 = 0x100000001`；`prepare_creds()` 里 `key_get()` 对它
    `atomic_inc` → 写未映射地址。
- **正确做法**：**任何写或副作用落进 `0x50~0x68`，终值必须是 NULL 或有效指针。**
  六写完成后在用户态 dump 假 cred 的 `0x50~0x70`，四个 keyring 字段（u64 视角）全零才放行。
  这次事件后定下的修法是：用户态直接清 `0x58/0x5c`（假 cred 本就在 RW 映射里，不需要 kwrite）。
- 出处：`research/root-retrospective.md` Part N.1 / N.7

### 14. `BUG_ON(task->cred != task->real_cred)` 不是"嫌疑"而是定理

- **症状**：清掉 keyring 后 `setresuid` 仍炸在 `commit_creds()` 第一行。
- **根因**：假 cred 是 `override_creds()` 装上的，而 override 的定义就是**只改 `task->cred`、
  不动 `task->real_cred`**。所以只要假 cred 还装着，这个 BUG_ON 必然触发。
- **正确做法**：别去"读指针确认嫌疑"（浪费一轮 probe）。直接 `fork()`：
  `copy_creds()` 走 `prepare_creds()` 但**不走 `commit_creds`**，且直接
  `p->cred = p->real_cred`，天然一致；子进程再 `setresuid(0,0,0)` 就合法了。
- 出处：`research/root-retrospective.md` Part N.2

### 15. `kread` 的长度由目标内存决定，`imsf_numsrc` 救不了

- **症状**：想读 `.data` 段（`selinux_enforcing`、`panic_on_oops`），读回来 0 字节。
- **根因**：`ip_mc_msfget` 的拷贝长度 = `psl->sl_count`，即 target-20 处那个 u32 的值。
  `.data` 大段为 0 → 拷 0 字节。3.10 的用户侧 `imsf_numsrc` 只做缓冲上限校验，
  **没有"用它当长度"的逻辑**。
- **正确做法**：① 锚定条件放宽（kread 只需 target-20 处**非零**，不必 ∈0..9，那是 kwrite 的条件）；
  ② 先找 `/proc` `/sys` 镜像（这两个目标都有）；③ 别为"确认字段偏移"再跑一轮 probe。
- 出处：`research/root-retrospective.md` Part N.6

### 16. 日志基建比 exploit 晚 18 小时

- **症状**："竞速连续 5 次失败""进程卡死""probe51 必崩"——一堆神秘现象。
- **根因**：SELinux 封掉几乎所有 syscall 通道，没有观测手段；
  真相是竞速**全赢了只是看不见**，"卡死"是 `sleepms` 的 `tv_nsec=1e9` 返回 EINVAL。
- **正确做法**：进攻性实验前先建**不可被绕过的观测通道**。这台机器上答案是
  "共享匿名页 + fork 抄写员"（约 30 行）：父进程写、子进程落地，绕过 SELinux 的所有写限制。
- 出处：`research/root-retrospective.md` §A.2 弯路②

### 17. 用 live 实验回答静态问题

- **症状**：为了回答"哪个域有 `setenforce` 权限"，在真机上逐个 probe（probe49/50/78）。
- **根因**：`/sepolicy`（307KB）早就 dump 在硬盘上了，逐类型扫权限是**纯离线**问题；
  "锚点存不存在"也是 `kimg.bin`（32MB runtime dump）的纯函数。
- **正确做法**：每个问题先问一遍"**这个答案是不是已经在磁盘上了**"。
  `analysis/selinux/sepolicy_parse.py` 落地后两小时就证伪了路线 G（user 版策略对
  `load_policy`/`setenforce` 零授权），省下的设备实验无法计数。
- 出处：`research/root-retrospective.md` §A.2 弯路③、Part M.1

### 18. `getprop` 一次只接受一个参数

- **症状**：`getprop a b c` 静默只输出第一个。
- **正确做法**：一次一个，或者用 `getprop | grep`。
- 出处：`history/工作日志.md`

### 19. toybox `dd` 没有 `conv=`，块设备也不用 `O_TRUNC`

- **症状**：`dd conv=notrunc` 直接报错。
- **正确做法**：块设备忽略 `O_TRUNC`，**直接 `seek=` 即可**，不需要 `conv=notrunc`。
- 出处：`history/工作日志.md`（TA 单字节写入）

### 20. 提权进程的挂载命名空间不是 init 的

- **症状**：remount `/data` 报 EPERM，于是判断"mount(2) 整体被拒"。
- **根因**：提权进程带 app 的 SELinux 域（`untrusted_app`）与**私有挂载命名空间**
  （`mnt:[4026536745]` vs init `4026531840`）；被拒的是"剥掉 `nosuid,nodev` 的 remount"，
  撞的是 `MNT_LOCK_NODEV/NOSUID`。`MNT_LOCKED` 在 3.10.84 **不存在**。
- **正确做法**：贴错 EPERM 时先看 `/proc/self/mountinfo` 与自身的 mount namespace，
  再判断是"锁"还是"权限"；`setns(/proc/1/ns/mnt)` 是绕开继承锁的出口（需单线程）。
- 出处：`research/bl-exploration.md` §8

---

## 三、环境与工具

### 21. 官方 x86 二进制在 arm64 上跑不起来

- **症状**：Flashtool 与 newflasher 的官方 x86 二进制全部跑不起来；`brew install` 在受限环境里不可用。
- **正确做法**：从源码原生编译（clang，Mach-O arm64）。libusb 的 `configure` 依赖 `rm`（受限 shell 里被拦），
  就**手写 `config.h`** 绕开 autotools，直接编 9 个 `.o` 打成静态库。
- 出处：`docs/guides/build-newflasher.md`

### 22. 设备 dump 有"窗口"：`/mnt/su` 开机后约 18 秒才出现

- **症状**：重启后立刻脚本化 dump，大量 `Permission denied`。
- **根因**：临时 root 依赖 APK 的 exploit 跑完；`/mnt/su` 出现前 shell 只有 uid 2000。
- **正确做法**：先轮询 `/mnt/su` 可执行，再做任何需要 root 的读取；脚本里加超时与重试。
- 出处：`apps/z5root` 的 `BootReceiver` 逻辑、`scripts/device/bl_dump.sh`

### 23. 设备离线导致外部验证迟到，结论被迫挂"待验证"

- **症状**：§4-A 的"记录格式外部验证"挂了两天，期间所有 unit 内容结论都带保留意见。
- **正确做法**：把"需要设备在线"的验证项**提前到一批**（一次连线做完所有只读验证），
  不要分散在多轮里等设备。
- 出处：`research/bl-conclusions.md` §7.2

---

## 四、方法论（最容易重复踩）

### 24. 把"能写进去"当成主问题

- **症状**：前几轮全部精力在"怎么把字节写进 TA/`/system`"，甚至准备恢复链路。
- **根因**：写进去**不算数**——`0x7DA`/`0x1046C` 都被 S1 根私钥签名，
  改完必被拒；`/system` 被 verity 锚在已签名的 boot.img 里。
- **正确做法**：先确认"**写了算不算数**"（信任锚在哪），再投入写原语。
  判据：找到"最终做 if 的那条指令"和"它读的数据由谁签"。
- 出处：`research/bl-conclusions.md` §0、§3

### 25. 把"`Command not allowed`"归因成"码不对"

- **症状**：以为买个解锁码就能过。
- **根因**：标准实现里格式错会先报 `Incorrect format`；这里是**在解析 code 之前**就拒，
  说明门在策略层（rooting 判定）。
- **正确做法**：用**响应文本**区分失败阶段。典型判据：gate 打开后裸 `oem unlock` 会变成
  `Incorrect format for unlock data...`，这是最干净的观测信号（零 wipe 风险）。
- 出处：`research/bl-export-and-analysis.md` §三、`bl-review.md` §9.4

### 26. 交叉评审要能证伪，不能只做"确认"

- **观察**：引入第二个模型（GLM）后，它第一轮就证伪了"`mount(2)` 整体被拒"这个核心归因，
  第二轮破译了 verity 尾部布局；但它也给了三处不准确的数字，被复核纠正。
- **做法**：评审要求"指出哪条证据不足、哪条结论越界"，而不是"总结得对不对"；
  收到评审后**逐条重验**（既不盲信也不护短），并在文档里写清"采纳/反驳/存疑"。
- 出处：`research/bl-review.md`、`bl-conclusions.md` §8
