# 0004 · 不再追求全局 permissive，改走 relabel

- **状态**：已采纳（2026-11-11，取代 R2 前期路线）· **2026-11-13 收窄适用范围**，见文末「事后修正」
- **相关**：`../research/root-retrospective.md` Part B / Part M

## 背景

R2 的大部分时间花在"怎么把 SELinux 变 permissive"上。代价是三起事故：

- 清 `ss_initialized` 再回灌策略 → `security_load_policy()` 的某条分支**重建 sidtab**
  → 所有已分配 SID 打乱 → relabel 补丁失效、SystemUI 崩溃循环、"相机硬件坏了"误诊。
- 外部复盘提出的"最优解"（init 域策略热加载，路线 G）在 `sepolicy_parse.py` 落地后**两小时证伪**：
  user 版策略对 `load_policy` / `setenforce` **零授权**（那条授权只存在于 userdebug 基线）。

## 决定

**不再动全局开关**，改用纯授权内的 **relabel 链**：
`type_transition` + `relabelto` + shell execute 权限，把目标文件打成 shell 能执行、init 能 relabel 的类型。

## 依据

SELinux 在这台机器上同时干两件事，而它们**由不同开关控制**：

| 手法 | 裁决（allow/deny） | 打标签（xattr / tsec） | sidtab | 结果 |
|---|---|---|---|---|
| `setenforce 0` / 清 `selinux_enforcing` | 关 | 保留 | 保留 | 全局放行 |
| 清 `ss_initialized` 回灌 | 关 | **坏** | **重建** | 事故源头 |
| 换 `security_ops` | 关 | 坏（延迟到下次开机） | 保留 | 污染延后 |
| **relabel（本决策）** | **不动** | **正常** | **不动** | **干净** |

即：需求是"让某个文件能被执行/被读"或"让某个进程拿到某个域"，
**不需要拆掉全局面板**。

## 后果

- ✅ 零 permissive、零内核写、零 sidtab 风险；重启即恢复原状。
- ✅ 与"临时 root"的干净失效语义一致（ADR 0001）。
- ⚠️ 需要先离线解析 `/sepolicy` 确认目标域对目标类型有 `execute`/`relabelto`
  （用 `../../analysis/selinux/sepolicy_parse.py`，不要上机试）。
- ⚠️ 最终落点：su 打成 `u:object_r:shell_data_file:s0`（不是 `shell_tmpfs`——
  shell 对 `shell_data_file` 的 `execute,execute_no_trans,open` 全齐，init 有 `relabelto`）。

## 教训

"把任何奇技当地基之前，读完它调用的所有函数的源码，尤其分支结构。"
`security_load_policy()` 的两条分支就写在后来自己被引用的那份源码里。

## 事后修正（2026-11-13）

上面"零 permissive"只对**拿到执行权的中间步骤**成立：relabel 链确实替代了
"拆全局面板"来让目标文件可执行。

但最终交付的 APK 在改写 `cred` 之后**仍然写了 `selinux_enforcing=0`**——
su 守护进程要跨域操作，仅靠 relabel 不够。所以生产版本的代价是
**root 在位期间 permissive**（见 [`../status.md`](../status.md) 的"已知代价"）。

两者不矛盾：仍然成立的决策是「不用拆 global 开关作为常规执行权手段」；
被收窄的是「整个 exploit 全程不碰 permissive」这一更强的表述。
