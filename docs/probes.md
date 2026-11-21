# 探针谱系：试过什么、死在哪、源码为什么不在了

> 2026-11-21 整理。R1~R2 期间在设备上跑过 **171 个 C/汇编探针**，一个探针 = 一次
> "改一个假设再试"。最终只有一条链跑通。这份文档替代那 160 多份中间版本源码：
> **每条死路都记下"试了什么 / 为什么死 / 细节在哪一节"**，需要复核时按索引回原文，
> 而不是翻一堆只差几行的 `.c`。
>
> 保留的源码只有 4 份（外加 3 个构建/运行小工具，见文末「现存源码」），其余已删除。

## 为什么删

这些版本 95% 的内容是同一份 exploit 的复制粘贴，差异只在：

- 写内核的偏移/字段（`0x58`、`0x60`、`process_keyring`……）
- 报告通道（socket → mmap 共享页 → kmsg 镜像）
- 竞速参数（线程数、钉核、重试次数）

它们**没有被验证为可用的版本**，留着只会让下一个人误以为其中某份是"对的"。
真正有价值的是"哪一步为什么错"，那部分在 `docs/history/` 与 `docs/pitfalls.md` 里。

## 谱系总表

| 范围 | 试的是什么 | 结局 | 细节 |
|---|---|---|---|
| `kgsl2`~`kgsl12`、`kgsl_probe`、`mmfix*`、`mmrd*`、`rtest*`、`surface*`、`open_probe`、`devprobe`、`hello` | KGSL（GPU）Dirty COW 变体：GPU 侧写 USERMEM / GPU 取指执行 | ⛔ **判死**。GPU 写 USERMEM 类映射 → IOMMU Permission Fault；CPU 侧 mmap 被 `memdesc.ops=NULL` 堵死 | `timeline.md` R1；ADR [0003](decisions/0003-pick-phoenix-talon-not-kgsl.md) |
| `probe2`~`probe34` | 建立任意读（`ip_mc_msfget`）与 4 字节写原语（`ip_mc_source`） | ✅ 原语成立，但写有硬约束 | 工作日志 §2.3、§9.1 |
| `probe36`~`probe47` | 直接改自己 `cred`；`setenforce` 提权 | ⛔ 改 cred 不稳；kernel 域 `setenforce` 被 SELinux 拒 | 工作日志 §9.3、§12.2 |
| `probe48`~`probe54` | 盲区问题：mmap 报告通道；暴力枚举 40 个域；`reset_security_ops`；`sel_write_disable` | ⛔ 域枚举全败；monolithic `security_ops` 复位必崩；`sel_write_disable` 恒 `EINVAL` | 工作日志 §13、§14.1~14.3 |
| `probe55`~`probe57` | 清 `ss_initialized` + 从 `/sepolicy` 回灌，让内核自己置回 1 | ★ **第一次拿到 permissive**，但代价是 sidtab 重建 | 工作日志 §14.10；`pitfalls.md` 第 1 条 |
| `probe58`/`probe59` | 装 `su`、拿可用 root shell | ★ 达成 | 工作日志 §15 |
| `probe60`~`probe64` | 持久化尝试：`/system` remount、`setns`、挂载标志矩阵、setuid 位 | ⛔ `MNT_LOCK_READONLY` + 块层 ro + dm-verity 三重墙；probe64 虽 root 到手但不可持久 | 工作日志 §15.5~15.10；ADR [0001](decisions/0001-temporary-root-only.md) |
| `probe66`~`probe77` | APK 化：自愈、崩溃续跑；SystemUI 崩溃循环与相机"故障"排查；双状态验收 | ★ probe77 双状态验收通过；中途两次误诊（相机、多任务） | 工作日志 §17~§22 |
| `probe78`/`probe79` | 共享匿名页日志；按名字换域（`find_task_pref`） | probe78 ★ 拿到决定性日志；probe79 找错方向（`init` sid 猜成 `0x25`，实际 `7`） | 交接文档 §7、§19.4 |
| `probe80`~`probe89` | `cred` 与 `rcu_head` 别名假设；赢后清指针、换 ret gadget、延长 panic 窗口 | ⛔ 全部仍在 ~98s 复位。`panic=10` 写入被拒；加判断反而抢不到竞态 | 交接文档 §21.4~21.6 |
| `probe90`~`probe99` | kmsg 行级镜像；竞速统计；"假失败"排查 | ⛔ 多数"失败"其实是仪表问题（日志被截断），不是竞速输 | 工作日志 §（kmsg 镜像段）、`pitfalls.md` |
| `probe100`~`probe111` | 六写 cred（`uid/gid/euid/egid/fsuid/fsgid`） | ⛔ 第 3/6 写的副作用落到 `0x60 thread_keyring` → 野指针 → **九连崩** | `pitfalls.md`；工作日志 §（0x60 段） |
| `probe112`~`probe122` | init 域拿到手；cred 替换 | probe114/117/121 稳定；probe115/116/122（带 `setresuid`/`setgroups`）必 panic | 交接文档 §32.4 |
| `probe123`~`probe136` | `kread` 遍历 `task_struct`；`kdec` 解码 | ⛔ 900 次遍历耗尽 `sk_omem_alloc`（`optmem_max=20480`），原语自己挂了 | 交接文档 §32.4 末 |
| `probe138`~`probe149` | 竞速定型；`fork()` 走 `copy_creds()` 绕 `BUG_ON`；RCU 回调链收口 | ★ **probe149s 打通**（`probe_app` 为 APK 相对路径版） | `timeline.md` R2 末；交接文档 §33 |
| `z5c.c` | 最小客户端（连抽象 socket 调试） | 工具，保留 | — |
| `capchk.c` | 只打印自身 capability（验证 exec 后满 caps） | 工具，保留 | — |

## 三件最贵的教训（都在上表里重复出现过）

1. **仪表问题会被误判成原理问题。** 「竞速连续 5 次失败」和「进程卡死」有相当一部分
   是日志通道被 SELinux 拒、或 `tv_nsec=1e9` 返回 `EINVAL`。先修观测，再改代码。
2. **静态可答的问题不要上机。** 域枚举（`probe49`）跑了几十次，答案其实在 `/sepolicy` 里；
   `ss_initialized` 的后果也是读 `security_load_policy()` 就能推出来。
3. **副作用比主效果更难防。** 六写 cred 的主效果每次都对，死的是第 3/6 写顺带踩到的
   `0x60` 野指针。写内核时"这一笔还会碰到谁"必须逐字段算。

## 现存源码

```
analysis/probes/device/probe_app.c   # 最终 exploit，APK 内版本（相对路径）
analysis/probes/device/probe149s.c   # 同一逻辑的 adb 版（绝对路径 /data/local/tmp）
analysis/probes/device/z5c.c         # 最小客户端
analysis/probes/device/capchk.c      # capability 打印（验证用）
analysis/probes/device/mkelf.py      # .o → 裸 ELF 打包（无 ld.lld 时的替代）
analysis/probes/device/go.sh         # 设备侧运行包装（拉起探针 + 起日志采集）
analysis/probes/device/ks.sh         # 内核日志采集（每 0.2s 追加 dmesg 尾 80 行）
analysis/probes/su/su.c              # setuid 客户端
apps/z5root/src|stubs/**             # APK Java 侧
apps/sutest/src/**                   # 第三方调用验证 app
```

`probe_app.c` + `su.c` 就是完整的提权链，`apps/z5root/build-assets.sh` 把**这两份**编成
APK 的 `assets/z5root` 与 `assets/su`（产物与 2026-11-11 的二进制逐字节一致）。

`probe149s.c` **不参与 APK 构建**——它是同一条链的 adb 手工版（绝对路径落在 `/data/local/tmp`），
留着是为了能在不装 APK 的情况下复跑同一份 payload。

## 要考古怎么办

- 想知道"某一步当时怎么想的" → `docs/history/交接文档_2026-11-09.md`（按上表节号）
  与 `docs/history/工作日志.md`（2724 行，按 `probeNN` 搜）。
- 想看某个中间版本的实际代码 → 早期两次提交里还有（`git log --all -- '*probe107s.c'`）。
  若历史被重写则不再保留——这是有意的：**记录结论，不囤积半成品**。
