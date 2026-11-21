# 0003 · 提权选 Phoenix Talon，不再挖 KGSL

- **状态**：已采纳（2026-11-07）
- **相关**：`../research/root-lpe-attack-surface.md`

## 背景

首轮攻击面测绘得到三条基础事实：**无 KASLR**、**SELinux 只封 socket 族不封字符设备**、
**无 PAN/PXN**。按"入口可达性 + 利用条件"排，最强入口是 `/dev/kgsl-3d0`（open + ioctl 全通）。

KGSL 的 Dirty COW 变体（c70b4f8）用 kgsl2~12 系列探针验证到底：

- GPU 取指/执行链路**完全打通**（dmesg 证实 IB 被 GPU 执行）；
- 但 GPU **写** USERMEM 类映射 → IOMMU Permission Fault（对 anon RW 页同样）；
- CPU 侧 mmap 被 `memdesc.ops=NULL` 堵死；
- GPU 写 kernel 分配的 GPUMEM **正常** → 说明加固只针对 USERMEM 类，不是全局禁写。

**结论：设备二进制（2016-07 构建）已包含比 copyleft 源码更新的高通加固补丁**，
`kernel-exact` 源码只是结构参考，与二进制有偏差。

## 决定

放弃 KGSL，转向 **CVE-2017-8890（Phoenix Talon）**：`MCAST_JOIN_GROUP` + `accept()` 让 `newsk`
继承父 socket 的 `mc_list` 指针 → 双双 close → `ip_mc_socklist` 被 `kfree_rcu` 两次。

## 后果

- ✅ 触发链在一个下午内全部实测打通（`socket` → `setsockopt` → `bind/listen/accept` → 双 `close`）。
- ✅ 利用条件正好被本机满足：无 KASLR（静态算 `cred`/`selinux_enforcing`）、
  无 PAN/PXN（`ret2usr`，RCU 回调 `func` 直接指向用户态）、SLUB 无 debug（静默双 free）。
- ⚠️ 副作用：这条链会**长期持有一个 UAF socket**，同名进程 `z5root` 不能被 kill
  （退出时 `ip_mc_drop_socket` 可能 panic）。
- ⚠️ 建 UAF 阶段有约 40% 概率触发内核 panic（黑屏重启一次），APK 用 `BootReceiver` 续跑兜住。

## 教训（写进 `pitfalls.md` 第 24 条）

"设备二进制不一定等于源码"。任何依赖特定 commit 行为的利用，**必须在目标二进制上验证**，
不能只看 copyleft 源码。
