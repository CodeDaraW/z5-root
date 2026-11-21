# 术语表

按领域分组。带 ⚠️ 的是**容易误解**的条目。

## 设备与分区

| 术语 | 含义 |
|---|---|
| **SO-01H / sumire** | docomo 版 Xperia Z5。sumire 是索尼内部代号。另有国际版 E6653，固件可跨刷但不建议 |
| **MSM8994** | 高通骁龙 810 平台代号 |
| **aboot** | 高通 LK（Little Kernel）引导器，**fastboot 的实现者**，也是 BL 解锁判定的所在地。ARM ELF32，基址 `0x3E000000` |
| **sbl1 / s1sbl** | 高通二级引导器 / 索尼 S1 二级引导器。`sbl1` 每次开机往 TA 尾部写启动日志 |
| **tz / hyp** | TrustZone 与 Hypervisor 镜像 |
| **TA（Trim Area）** | 索尼的配置分区（`mmcblk0p1`，2MB）：机型/运营商/锁状态/DRM keys/校准/IMEI。**明文**，无整盘加密 |
| **devinfo / keystore** | 本机上这两个分区**全 0**（`devinfo` 全 0 意味着没有常规的解锁标志位） |
| **dm-0** | `/system` 的 device-mapper 映射设备，verity 的读取入口。比裸分区 `p44` **短 43MB**（那是哈希树+元数据） |
| **p44** | `/system` 的裸块设备（`mmcblk0p44`）。内容与 dm-0 相同，但**绕过 verity** |
| **/mnt** | tmpfs。临时 root 的 su 落点 `/mnt/su`，重启即消失 |

## 索尼 S1 体系（BL 解锁的核心）

| 术语 | 含义 |
|---|---|
| **S1** | 索尼的 bootloader 安全体系代号（`S1_Boot_MSM8994_LA1.2.2_42C`） |
| **S1 service** | ⚠️ **不是设备内的服务**，而是由**外部刷机工具**提供的插件接口。aboot 通过 `ctx+0x44` 句柄 + `blx` 回调调用它。`fastboot oem unlock` 提示"插刷机线"就是在等它 |
| **unit / unit id** | TA 里的记录单位，每条有 `uid`。配置类 unit 集中在 `off<0x40000`，日志类在 `off>=0x60000` |
| **tad** | TA 守护进程（`/dev/socket/tad`，socket 属组 `trimarea`=2993）。另有 `/dev/pta`(10,44) 与 `tad_static` 服务 |
| **TAD 协议** | 本项目破译的私有 RPC：`[u32 len+9][u8 ver=1][u32 a0][u32 op][payload]`，op 0=open / 2=getsize / 3=read / 4=write，全大端 |
| **bootconfig** | unit `0x84F` 的内容，Sony 私有 TLV 容器，魔数 `1A CE`。**内不含 rooting 字段** |
| **SIN 容器** | Sony 的签名数据容器：`03 "SIN"` + 头字段 + 载荷 + DER 证书 + `02 01 00` + RSA 签名 |
| **S1_SL** | ⚠️ **S**im**L**ock 证书（unit `0x851`），签发 `0x7DA` 配置文本。不是"security level" |
| **S1_RLock** | **R**emote **Lock** 证书（unit `0x1046C`），docomo 的运营商锁定数据 |
| **S1_HWConf** | 硬件配置/分区描述表（unit `0x7D3`），条目里列 `S1_RLock`、`S1_GCodes` 等 |
| **S1_GCodes** | 索尼的解锁码体系。本机**为空** |
| **S1_Root_f936** | S1 体系的**根证书/根私钥**（RSA-2048 / sha256WithRSA，2014–2034）。**缺的就是这把私钥** |
| **remote lock data** | `0x1046C` 里的 1042B SIN，由根私钥**直签**。官方解锁流程成功后由 S1 服务写入 |
| **`0x1046B`** | 16B "解锁请求"槽。**非空**说明官方流程被走到过一半；`Done` 分支会 `ta_clear` 它 |

## 安全机制

| 术语 | 含义 |
|---|---|
| **dm-verity** | 块级完整性校验。本机**已启用**，四证据：fstab `wait,verify` + `/verity_key` + `partition.system.verified=1` + dm-0 比 p44 短 43MB |
| **哈希树布局** | ⚠️ **root-first**：顶层块 = L1，L1 条目 = L0 块哈希，L0 条目 = 数据块哈希。magic `0xb001b001` 在**数据区末尾块**，不在分区尾 |
| **`/verity_key`** | boot.img ramdisk 里的验签公钥（524B，非 PEM/DER）。信任锚在**已签名的 boot.img** 内——这是持久改 `/system` 必须过 boot 链的原因 |
| **三堵墙** | `/system` 写不进去的三个独立原因：`MNT_LOCK_READONLY`（硬）+ 块层 ro（`BLKROSET` 可清，软）+ dm-verity |
| **MNT_LOCK_\*** | 挂载锁族。3.10.84 有 `MNT_LOCK_READONLY/NODEV/NOSUID`，**没有 `MNT_LOCKED`** |
| **BLKROSET** | 块设备只读标志的 ioctl。root 可清（`blockdev --setrw`），但清了也过不了 verity |
| **SELinux 域 / 类型** | 域=进程标签（`u:r:shell:s0`），类型=文件标签（`shell_data_file`）。"放行"与"打标签"是**两件独立的事** |
| **sidtab** | SELinux 的 SID 表。`security_load_policy()` 某条分支会**重建它**，打乱所有已分配 SID |
| **relabel** | 给文件换 SELinux 标签。纯授权内的干净路：`type_transition` + `relabelto` + execute 权限，**不需要 permissive** |
| **三件套** | aboot 里 `0x7DA` + `0x851` + `0x8B2` 三个 unit 一起送进处理链（入口 `0x3E03C678`）。⚠️ 早期被误称为"一起验签"，实际不验 |
| **bit1 / bit12** | 16 位位图 `[ctx+0x58]+0x1C`：**bit1 = rooting 允许**，bit12 = override（override 只打日志，**不改控制流**） |

## 内核提权

| 术语 | 含义 |
|---|---|
| **CVE-2016-5195** | Dirty COW。本机 2017-01 补丁**已修复**（`cowtest` 实测） |
| **CVE-2017-8890** | Phoenix Talon。`accept()` 继承父 socket 的 `mc_list` → 双 close → `kfree_rcu` double free。**本项目走的就是它** |
| **mc_list / ip_mc_socklist** | 组播成员链表。double free 的对象（kmalloc-96） |
| **KGSL** | 高通 GPU 驱动（`/dev/kgsl-3d0`）。其 Dirty COW 变体（c70b4f8）在本机**已加固**：GPU 写 USERMEM 触发 IOMMU PF、CPU mmap 被 `ops=NULL` 堵死 |
| **KASLR** | 内核地址随机化。本机**没有**——dmesg 打印固定布局，`.text @ 0xffffffc000080000` |
| **PAN / PXN** | 内核访问用户页的保护。本机**都没有** → `ret2usr` 可用 |
| **ret2usr** | 让内核执行用户态代码。这里通过劫持 RCU 回调的 `rcu.func` 实现 |
| **cred / real_cred** | 进程凭证。`override_creds()` 只改 `cred`，`commit_creds()` 才两者都改 |
| **keyring 区** | `struct cred` 的 `0x50~0x68`：session/process/thread/request_key_auth 四个指针。⚠️ **写脏必炸**，两次事故都在这 |
| **probeNN** | 探针编号（`analysis/probes/device/probeNN.c`）。编号是**历史顺序**，不代表重要性 |

## 项目内部用语

| 术语 | 含义 |
|---|---|
| **A / B / C 线** | A=内核提权（成功）、B=BL 解锁（判定不可行）、C=免解锁降级刷机（放弃） |
| **L1 / L2** | L1=adb 可用 su + 系统正常（已达成）；L2=任意 app 可调用 root（`/mnt/su` 也达成，代价是无授权弹窗） |
| **【实测】/【强推断】/【推测】** | 可信度三档，见 `docs/README.md` |
| **DS / GLM** | 两个模型角色的历史称谓：DS 主攻（做实验、写文档），GLM 交叉复审（只做点评与便宜验证） |
