# Z5 Root 项目 · 外部复盘与下一步路线建议

> **📁 路径说明**：文中的 `bl/bl/`、`dump/`、`exploit/probe/` 等旧路径是写作当时的，
> 换算表见 [README.md](README.md)「路径对照」。标题里的文件名见同页「命名对照」。

> 写给：接手本项目的模型（DS）／任何继续这条线的人
> 素材：`report/交接文档_2026-11-09.md`（614 行）+ `report/工作日志.md`（2724 行，24 节）全文精读
> 性质：路线级评审，非逐行审计。所有标注【待验证】的条目，都能用你手里的 `kernel-exact/` 源码 + `dump/` 离线定案，或一次已提权会话内实测。
> 引用格式：`§x.y` 指交接文档章节；`日志§x` 指工作日志章节。

---

## 0. 60 秒版结论

1. **exploit 核心已经完工**：竞速 3/4、原语齐备、提权稳定、APK 可分发。当前"没法稳定使用"的病根 **100% 在"获取 permissive"那一步（ss_initialized=0 自伤），不在 exploit 本身**。
2. 交接文档 §7-4（"装 su 和变 permissive 是两件独立的事"）是全文档最有价值的一句话，但没有推到底。**验收应拆成两层：L1（adb 可用 su + 系统正常）可能只差一次回归测试；L2（App 可调用 root）才需要新架构。**
3. 有一个被 A~F 六条路线全部漏掉的**最优解：init 域策略热加载**（见 §D）。它同时满足：sidtab 无损、打标签照常、重启零残留。
4. **路线 C（换 security_ops）并不"零污染"**——它把污染延迟到了下一次开机（见 §C.1），且与证伪表里的 probe51 自相矛盾。
5. **Q1/Q2 是离线可答的问题**，不需要上机：`/sepolicy` 解析 + `kimg.bin` 锚点扫描，两个各半天的工具，把"锚点彩票"变成系统性普查。

---

## Part A · 复盘：这 24 小时做对了什么、在哪里走弯路

### A.1 值得保持的东西（不夸张，这是专业水准）

| 项 | 评价 |
|---|---|
| 实证纪律 | 全程"实测，不是查资料"；12 条证伪表（§8）+ 每条带证据。这是正确的科研姿势 |
| 自我纠错能力 | 三次重大改判（日志§19→20 相机平反；日志§23 sidtab 真因；日志§24 "日志消失≠失败"），其中两次是被用户实测打脸后认账。罕见且珍贵 |
| 三代日志基建 | 共享匿名页 + fork 抄写员（§4.6）是教科书级设计——SELinux 封锁一切 syscall 通道时用纯用户态 store 出日志 |
| 交接文档结构 | 60 秒摘要 / 验收标准 / 复现手册 / 操作禁忌 / 证伪表。比多数人类渗透团队的 handover 好 |
| 离线工具链 | 无 NDK、无网络，手搓 mkelf.py / axml.py / 864B su / D8+jarsigner 打包链 |
| §11 的实验经济学 | "2、3 合并进一次已提权会话里顺手做完"——正确的省钱思路 |

### A.2 三次主要弯路（按代价排序）

**弯路 ①（最大）：probe55 设计时没读 `security_load_policy()` 的两个分支。**
sidtab 重建（日志§23.2 的真因）写在你们自己后来引用的源码里（`kernel-exact/security/selinux/ss/services.c`）。设计"清 ss_initialized 再回灌"这一刀之前，把它的完整 callee 读一遍，probe70~77 十几个小时的 relabel 补丁、"相机硬件坏了"的误诊、SystemUI 崩溃循环系列事故，全部可以避免。
**教训：把任何"奇技"当地基之前，读完它调用的所有函数的源码，尤其是分支结构。**

**弯路 ②：日志基建晚了 ~18 小时。**
共享页抄写员只有 ~30 行。它就位之前，"竞速连续 5 次失败"（日志§24 揭穿：其实全赢了，只是看不见）、"进程卡死"（其实是 sleepms 的 tv_nsec=1e9 EINVAL）、probe51 时代的"必崩"（根因至今是推测）——相当一部分"神秘现象"是仪器问题不是目标问题。日志§24 你们自己也意识到了。
**教训：进攻性实验前，先把不可绕过的观测通道建好。在这台机器上，"提权后还能出日志"就是不可绕过的。**

**弯路 ③：用 live 实验回答静态问题。**
Q1（哪个域有 setenforce）——`/sepolicy` 307380 字节早就 dump 下来了，逐类型扫描权限是纯离线问题；probe49/50/78 却在真机上一个个试（且只试到 init/kernel 两个）。Q2（锚点存不存在）——是内核内存内容的纯函数，`kimg.bin` 32MB runtime dump 就在手边，probe80 却设计成上机实验。
**教训：每个问题先问"这个答案是不是已经在磁盘上了"。**

---

## Part B · 认知框架修正（本评审的核心贡献）

### B.1 "放行"和"打标签"是两件独立的事

SELinux 在这台机器上同时干两件事：
- **裁决**（deny/allow）——由 enforcing 状态、域权限决定；
- **打标签**（`inode_init_security` 给新建文件写 `security.selinux` xattr、`cred_prepare` 给新进程发 tsec）——由 hooks 挂着 + policydb/sidtab 有效决定。

三种"搞掉 SELinux"的手法，动的其实是不同的开关：

| 手法 | 裁决 | 打标签 | sidtab | 后果 |
|---|---|---|---|---|
| `ss_initialized=0` + 回灌 | 关→回 | **关**（窗口内新文件无 xattr） | **重建作废** | 同 boot 全系统 unlabeled + 下次开机新文件 unlabeled。毒（已实证） |
| 换 `security_ops` → default（路线 C） | 关 | **关**（`inode_init_security` 变 cap 桩） | 完好 | **root 会话期间所有新建文件无 xattr → 下次开机 unlabeled → 崩溃循环。不是零污染，是污染记账延期**（见 §C.1） |
| permissive / 域级 permissive | 关（allow+audit） | **开** | 完好 | 干净。日志§22 的 B 态在 permissive 下全绿已实证 |

**推论：干净的放行只有一种形态——保持 hooks 和 sidtab 完好，只在裁决层让步。** 这直接决定路线排序（见 Part F）。

### B.2 验收分两层，别混着追

- **L1（交接文档 §1 验收表 A/B/C 的字面）**：开机手动触发 → 有可用 su（adb 侧）→ 无论是否触发系统都正常 → 重启零残留。
  **probe78 形态的链（提权 → kernel 域 + 全 caps → 装 /mnt/su → 不碰 ss_initialized → 不做任何 relabel → hang 常驻）就是 L1 的形状。**§24.5 的 H 行已实证 su 装得成。差的只是：把 probe78 逻辑打进 APK + 完整跑一遍 §22 的验收套件（×3 个 boot）。
  另注：竞速失败（~1/4）中"早期 panic"无害、重启再点即可；"卡死"型失败需要用户手动重启（App 无权自行 reboot，`PowerManager.reboot` 要系统签名）。这要写进使用说明，是可接受的 UX 代价。
- **L2（用户在日志§15 的原始诉求）**："su 能被 App 调用"。被 §18.4 的 CapBnd=0 物理封死后，只能换架构（root 代理 daemon）。**注意 L2 有两个未被审视的 SELinux 门槛**（见 §E.3）。

> 交接文档 §16 说"难点已经不在拿到 uid 0，而在拿到之后怎么不把 SELinux 拆坏"——方向对。补一句：**最稳的"不拆坏"是根本不去拆，只在自己的进程身上想办法（域级放行 / 变色龙），全局面板一根手指都别碰。**

---

## Part C · 对交接文档的具体纠错清单（逐条，可执行）

### C.1 路线 C（换 security_ops）的两个硬伤

**硬伤 ①：跨 boot 污染。** `security_ops` 指向 default_security_ops 后，`security_inode_init_security` 走 cap 桩返回 0 → root 会话期间**每一个新建文件都不带 `security.selinux` xattr**。而 system_server 每隔几秒就在写 settings（AtomicFile 是"写新临时文件 + rename"）、packages.xml、appops……下一次开机（Enforcing、原策略）这些文件全部 unlabeled → SettingsProvider 在 system_server 里读设置被拒 → **正是日志§17/§20 那种崩溃循环，只是延迟一个 reboot 触发**。验收 C（重启无残留损坏）直接违反。除非 ops 换回（见 ②），否则 root 会话越长毒越深——而 daemon 形态的会话是"直到关机"。
**硬伤 ②：换回需要第二次写同一地址。** 恢复 = 把 0xffffffc00187bc18 再写回 0x01649388。锚点是否支持同地址二次写，取决于该位置前 24~60 字节里是否存在**第二个**锚点（第一个被 sl_count++ 吃掉后，其它候选词仍在）。可离线判定（§E.2）。另外即使换回，窗口期内已创建的无 xattr 文件**永久带毒**，需要下次开机后 relabel 自愈方案——又是一摊子事。
**结论：路线 C 从"最优雅"降级为"仅限短窗口、且需先解决换回与自愈"。优先级降到策略热加载（Part D）之后。**

### C.2 路线 C 与 probe51 的内部矛盾（交接文档没意识到）

证伪表（§8）："reset_security_ops() 走 RCU｜❌ 必崩｜probe51"。路线 C 做的**内存突变与 probe51 完全相同**（`security_ops` → default 表），一个被钉进棺材、一个被评为最优雅。probe51 的崩溃根因只有推测分析（残留 netfilter hook `selinux_ipv4_ops`，网络包一到，`sk->sk_security` 为 NULL 的 socket 被 hook 解引用）。当时没有共享页日志——日志§24 的教训（"日志消失≠失败"）完全适用于否定这次"实测"。
**行动项：若路线 C 复活，必须先用现代仪器重跑 probe51 场景（换 ops → 立刻灌网络流量 → 看共享页日志走到哪、oops 在哪）。附带缓解线索：若 kernel-exact 里 selinux 的 nf hook 开头有 `if (!selinux_enabled) return NF_ACCEPT;` 守卫，则配合 `selinux_enabled=0`（锚点离线查）可拆掉这个雷——这是源码一分钟能定案的事。【待验证】**

### C.3 Q2 框错了：换 security_ops 根本不需要 8 字节写

`security_ops`（0xffffffc00187bc18）、`selinux_ops`（0xffffffc001649388）、`default_security_ops`（0xffffffc001645898）**高 32 位同为 0xffffffc0**。因此只需在 0xffffffc00187bc18 写**一次 4 字节、值 0x01645898**，指针即变为 default_security_ops。Q2 的"两次 4 字节写 + 各自锚点"、以及为它服务的整个路线 D（IP_MSFILTER 批量写），对路线 C 而言是过度设计。
（路线 D 作为通用"一次写 4N 字节"技术仍有独立价值，见 C.4。）

### C.4 "同一地址一 boot 只能写一次"需要修正：锚点可以链式推进

交接文档 §4.3 约束 2 的准确表述应是"**同一地址**一 boot 只能写一次"。连续地址是另一回事：
- 第一次写（锚点 k）后 `sl_count` 变为 k+1；
- 对 **W+4** 再做一次 `IP_BLOCK_SOURCE`，kwrite 扫描 k'=k+1 时，sl_count 词（正是被 +1 的那个词）== k+1 成立，sl_max 词 = 原锚点对的 sl_max（要求它 ≠ k+1，即原 sl_max 同时 ≠ k 和 ≠ k+1）；
- 写入点 sl_addr[k+1] = W+4。以此类推可写连续 4N 字节（N ≤ 10 - k）。
**真正的拦路虎是 memcmp 去重检查**：每次写入前，内核扫 `sl_addr[0..sl_count-1]`（即 W-4k..W 的既有内容，含已写入的值），若新值与窗口内任何 4 字节相同 → 视为"已存在" → 不写。写内核指针的高半 0xffffffc0 时，窗口里其它内核指针的高半就是 0xffffffc0 → **大概率撞车**。所以链式写适合写"内容独特的值串"，不适合写裸指针对。设计 kwrite_n 时必须把这个检查建进模拟器里（离线可精确模拟，见 §E.2）。

### C.5 probe79（setcon 按名换域）大概率死在 DYNTRANSITION

写 `/proc/self/attr/current` 换域，`selinux_setprocattr()` 里要走 `avc_has_perm(旧sid, 新sid, SECCLASS_PROCESS, PROCESS__DYNTRANSITION)`。user 版策略里 `allow X Y:process dyntransition` 的授予面≈零（userdebug 的 su.te 才有宽授予，且 user 编译根本不含 su 域——`security_context_to_sid` 就会先 -EINVAL）。**你们已经有不受此限的等价物：裸 sid 直写 tsec**（probe78 的 X 行：`X sid 00000025 ... ` 就是这么换到 init 的）。正确组合：
```
离线解析 /sepolicy → 得到 域名→type 编号
裸 sid 写 tsec（用户页，随时改）→ 绕过 setcon 的所有 syscall 层检查
```
setcon 这条路只在"需要内核替你做 context→sid 解析"时有意义，而 sid 解析离线就能做（见 §E.1 sidtab 读取）。**probe79 若已写好可以跑（成本 10 分钟），但预期值应下调到≈0，别为它排优先级。**

### C.6 交接文档 §4.5 与 §24.7 的矛盾必须先核实

§4.5：fake cred = init_cred 逐字节克隆 → `security`（0x70）指向 **init_cred 的真 tsec**（内核对象，sid=kernel）。
§24.7：说 setcon "改的就是我们那个**假 tsec 页**"（用户页）。
两者必有一处过时。这直接关系到：
- 若 tsec 是共享真对象：任何写 tsec->sid 的操作（setcon 或裸写）都会**连带改掉 init 和所有内核线程的域**——灾难；
- 若是用户页私有克隆：安全，而且"变色龙"架构（§E.4）成立。
**跑 probe79 / 做任何 tsec 写之前，先在代码里确认 probe79s.c 当前用的是哪种。**

### C.7 关机顺序与"干净重启"的验证

`do_exit` 的顺序是 `exit_mm()` **先于** `exit_files()`。持 UAF 的进程被 SIGKILL 时：地址空间先拆 → 用户页假 pmc 解除映射 → 随后 close 触发 `ip_mc_drop_socket` 走 mc_list → 对已解除映射地址取数 → oops →（panic_on_oops）panic。§18.2 的"强停 App 必 panic"与此吻合。
正常重启**看起来**没事（日志§18.3/§22.4），推测是 init 并不 SIGKILL 所有 app 进程就 reboot(2)，exit_files 从未发生。**但"看起来没事"≠"干净关机"：建议每次 root 会话重启后的下一个 boot 查 `dumpsys dropbox` 有无 SYSTEM_FSCK——若有，说明关机其实走了 panic 路径（ext4 journal 回放无害，但应当知情并在文档里如实记录）。**

### C.8 一个被 workaround 掩盖的未解之谜

日志§14.10 坑 1：提权后 mmap 一律 -EACCES，但 probe56 同样的调用却能成，"差异目前没定位"。未解释的异常不该被"提权前建好大缓冲"永久掩盖——**路线 B 的 daemon 长期运行，保不齐需要在提权后分配内存**。建议：一次已提权会话里做个 2×2 矩阵（提权前/后 × 域 kernel/init）各 mmap 一次，把差异定下来。

### C.9 顺手记录：考虑过但不推荐的思路——avc 节点投毒

想法：找到 `(ssid=1, tsid=1, tclass=security)` 的 avc 缓存节点（`avc_cache` @ 0xffffffc00187bc38，slot 可遍历），kwrite 把 `ae.avd.allowed` 补上 SETENFORCE 位 → kernel 域写 enforce 变合法。**锚点几何大概率不配合**：avc_node 布局（hlist_node 16B + rcu_head 16B + ssid/tsid/tclass + avd）里，`allowed` 前面的词几乎全是指针半字或非 0..9 的值，锚点对 (sl_max, sl_count) 落不进去。加上节点生命周期不可控（可被回收替换），投入产出比差。**仅当 §E.2 的离线锚点普查意外发现可用锚点时再回头。**

---

## Part D · 被漏掉的最优路线：init 域策略热加载（新增路线 G）

**这是本评审最重要的一条。A~F 六条路线（§10）里没有它，而它的每块零件你们都已经拿到手了。**

### D.1 机制

```
提权（kernel 域 + 全 caps）
→ 裸 sid 切到 init（probe78 已实证 sid=0x25 可用）
→ open("/sys/fs/selinux/load") + write(补丁过的策略 blob)
→ sel_write_load 的 av 检查：task_has_security(current, SECURITY__LOAD_POLICY)
→ init 域【必然通过——开机加载策略走的就是这同一个检查，否则起不了机】【待验证：离线解析确认】
→ security_load_policy 走 ss_initialized==1 的【正常 reload 分支】：
   policydb_read(新策略) + sidtab_map(clone_sid) + sidtab_map(convert_context)
   —— 即交接文档 §6.2 自己引用过的那段："编号全部保留，这才是内核热更新策略不出事的原因"
→ sidtab 无损（所有 inode/进程的 sid 继续有效）+ avc_ss_reset 干净刷缓存 + 打标签机制原封不动
```

### D.2 补丁内容（二选一，都是二进制 policydb 上的小编辑）

| 方案 | 编辑 | 效果 | 附带 |
|---|---|---|---|
| G-1 | 在 avtab 中找到 init 已有的 `allow init security:security {...}` 条目（load_policy 所在的那条），给它的许可位图**或上 SECURITY__SETENFORCE**（单 u32 位操作） | init 域获得 setenforce → 裸 sid=init → 写 enforce 文件 → **全局干净 permissive**（打标签照常） | 无 |
| G-2 | 在类型符号表里把 init 类型（或任一已知 sid 的类型）的 flags **翻成 permissive** | 该类型域级 permissive：自己的 denial 全部 allow+audit | 真 init 也变 permissive——它几乎没有 denial，无害；audit 噪声可忽略 |

格式说明书就是 `kernel-exact/security/selinux/ss/policydb.c`（policydb_read 的每个字段）。avtab 条目的位图、类型符号的 flags 偏移，读源码即可定。原 blob 307380 字节已 dump，编辑后 md5 校验。
**风险点：编辑后的 blob 必须能通过 policydb_read 的全部一致性检查（hash 链、长度对齐）。第一次实验建议在主机上用你们自己的解析器先读回验证一遍再上机。**

### D.3 为什么它同时满足验收 A/B/C

- **A（不触发）**：什么都没发生，系统原样。
- **B（触发后）**：daemon 进程 = init 域（permissive 或带 setenforce）→ 想干什么都行且**文件照常打标签**（permissive ≠ hooks 关闭——见 §B.1 对照表第三行，日志§22 B 态已实证 permissive 下系统全绿）。
- **C（重启）**：`/sepolicy` 在 boot 分区、dm-verity 只读、**我们从没碰过磁盘上的它**——只是通过 selinuxfs/load 喂了一份内存态补丁。下次开机加载原版策略，init 不再 permissive，一切归零。零残留、零 relabel、零 fsck 风险。

### D.4 待验证清单（全部低成本）

1. 【离线】init 确有 `security:security load_policy`（解析 /sepolicy，grep allow 规则）；
2. 【离线】二进制格式的 avtab 位图偏移 / 类型 permissive flags 偏移（读 policydb.c）；
3. 【源码】3.10 reload 分支确无额外坑（如对新策略的类型集合要求——补丁不增删类型/角色即可满足 convert_context）；
4. 【上机，一次已提权会话】裸 sid=init 后 `open+write` selinuxfs/load 的**行为探针**：先写原版 blob（未打补丁、内容合法）——若成功，reload 路径即实证打通，且这次写本身就是无害的（同策略热重载）；
5. 【上机】顺带确认 Android 6.0 该机型开机后 selinuxfs/load 节点仍可写、无额外硬化。

> 4 的"先写原版 blob"是整个 G 路线**零风险的关键实验设计**：成功 = 机制成立；被拒 = 记录 avc，Q 也就有了答案。一次竞速换来决定性结论，和你们 §11 的实验经济学一致。

---

## Part E · 离线工具优先：两个半天，换掉一半的设备实验

### E.1 `/sepolicy` 解析器（回答一切"谁有什么权限"）

输入：已 dump 的 307380 字节策略 + `kernel-exact/ss/*.c` 作为格式规范。
一次实现，永久回答：

- **Q1 终局答案**：全类型扫描 `allow T security:security setenforce`（不用再 live 试任何域；probe78 已测的 init/kernel 只是其中两个）；
- init 的 `load_policy`（D.4-1）；
- `dyntransition` 的全部授予（C.5 的定案）；
- 全部 permissive 类型清单（若策略里已有任一可用 permissive 类型，连 G-2 都不用打补丁——直接裸 sid 切进去）；
- **L2 的 app 侧权限矩阵**：`untrusted_app` 能 connect 的 sock_file 类型、能 exec 的文件类型、`appdomain` 的 unix socket 规则（见 E.3）；
- 类型名 → 编号映射（配合裸 sid 使用）。

实现提示：不用写完整语义分析，只需要 symbols 表（类型/类/角色）+ avtab 遍历 → 输出 `(source, target, class, perms)` 四元组表，然后随便 grep。kernel-exact 的 `policydb_read` 是权威字段顺序。

### E.2 `kimg.bin` 锚点扫描器（把锚点从彩票变成普查）

对 32MB dump 的 .data/.bss 段，**每个 4 字节对齐地址 W**，判定 k=0..9：
```
anchor(W, k) ⇔ word[W-20-4k] == k  且  word[W-24-4k] != k
```
用 `dump/kallsyms.map` 给命中位置标注：锚点词属于哪个符号的哪个偏移、**副作用词（sl_count++ 会改坏的那个字）属于谁**——这是报告里一直没做的一步：写入是有附带损伤的，必须知道损伤的是谁的什么字段。
输出一张"全内核可写位置清单"，然后对照愿望清单：
- `security_ops`（0xffffffc00187bc18）低半 —— 路线 C 的可行性定案；
- `selinux_enforcing`（0xffffffc00187d47c）—— 复核 probe78 的 -2000（顺带把 k=0..9 全窗口 dump 出来人工确认一次，排除 kwrite 实现笔误的可能）；
- `selinux_enabled`（0xffffffc001649380）—— C.2 的 nf 缓解；
- avc_node 各字段、nf hook 表项、modprobe_path —— 顺手全查了。

注意两点：① kimg.bin 是**某一 boot 的快照**，计数器/堆指针类词可能随 boot 漂移，命中后上机前要在当次会话里 kread 复核；② 同一扫描器稍加扩展就是 **kwrite 模拟器**（含 memcmp 去重检查和锚点链式推进的模拟，C.4 的"高半撞车"可以直接在离线预测）。

### E.3 L2 的两个未被审视的门槛（Q3 只回答了一半）

交接文档 Q3 全在问"**服务端**（kernel 域）能不能 socket/bind/exec/read"，没人问"**客户端**（untrusted_app）能不能连过来"。App 调 root 的完整链路是：
```
untrusted_app --connect--> sock_file（某标签） --stream--> daemon（某域） --fork+exec--> shell（某域）
```
每一跳都是一条 SELinux 检查。已知事实：App 的 CapBnd=0 封死了 setuid 路（§18.4）；`/data` 无 noexec 但 app 域对 `app_data_file:file execute` 是否授予【待离线确认，大概率无】。**因此 L2 的架构选型（socket 标签选什么、daemon/子进程戴什么域）应由 E.1 的权限矩阵反推，而不是先把 daemon 写出来再在真机上撞墙。**一个可能有用的既有事实：Android 6 策略里 app 域是能连某些 socket 的（如 `dnsproxyd_socket`）——若确认，daemon 创建 socket 后由全 caps 进程 lsetxattr 成该标签（需 relabelto 权限配合 permissive/init 域）是一个候选组合。

### E.4 顺手提炼一个架构级武器：域变色龙

probe78 的 X 行其实演示了一个没被命名的能力：**tsec 在用户页、sid 可以随时改、每次 syscall 的 SELinux 检查都实时读它**。这意味着 root 进程可以**按操作换帽子**——bind 时戴 A 域、fork+exec 时戴 B 域、读 /data/data 时戴 C 域——每个操作挑策略里最合适的域，而不需要一个全能域。路线 B 的"kernel 域贫弱"问题（日志§17.8 已实证）由此直接消解：kernel 域只用来做那几件它确实能做的事（装 su 已实证），其余操作切 init。
前提：先核实 C.6（tsec 必须是用户页私有副本，不是共享真对象）。

---

## Part F · 修正后的路线图（替代交接文档 §10/§11 的排序）

| 序 | 动作 | 回答什么 | 成本 | 风险 |
|---|---|---|---|---|
| 1 | **probe78 逻辑（去掉全部 relabel/ss_initialized）打进 APK，跑 §22 验收套件 ×3 boot** | L1 是否当场达标 | 半天 | 零 |
| 2 | **离线 /sepolicy 解析器**（E.1） | Q1 终局、load_policy、dyntransition、permissive 类型清单、L2 权限矩阵 | 半天 | 零 |
| 3 | **离线 kimg.bin 锚点扫描器 + kwrite 模拟器**（E.2） | 全目标锚点普查；C.3/C.4/C.9 定案 | 半天 | 零 |
| 4 | **一次已提权会话内的行为探针包**：①裸 sid=init 写原版 blob 到 selinuxfs/load（D.4-4）；②Q3 能力矩阵按"kernel/init 两顶帽子"跑（socket/bind/execve/读 /data/data/写 /data/system）；③C.8 的 mmap 2×2 矩阵；④dump security_ops±0x60 复核离线扫描结果 | G 路线可行性 + 路线 B 的域选择 | 一次竞速 | 低 |
| 5 | 视 2/4 结果二选一：**G-1/G-2 补丁策略加载**（需要 permissive 时）→ 变色龙 daemon + su 客户端（L2） | L2 | 1~2 天 | 中 |
| 6 | 路线 C 降级为备选；复活前提：重跑 probe51（共享页日志 + 网络流量冲击）+ 锚点扫描显示 security_ops 可写**且可写回** | 其真实死因 | — | — |

**排序逻辑**：1 先把已经到手的胜利落袋；2/3/4 全部是"一次投入、终身复用"的信息基础设施，且互相独立可并行；5 的架构决策被 2/4 的数据唯一确定，避免再出现"先写完再撞墙"；6 只在 G 失败时启用。

---

## Part G · 我无法远程定案、需要你离线/上机核实的清单

| # | 事项 | 核实方式 |
|---|---|---|
| 1 | 3.10 `selinux_setprocattr` 是否确有 PROCESS__DYNTRANSITION 检查 | kernel-exact 源码 1 分钟 |
| 2 | selinux nf hook 是否有 `!selinux_enabled` 守卫、是否解引用 `sk_security` 而无判空 | kernel-exact 源码 |
| 3 | init 是否有 load_policy（G 路线的地基） | E.1 解析 / kernel-exact + sepolicy |
| 4 | binary policydb 的 avtab 位图、类型 permissive flags 的确切偏移 | kernel-exact/ss/policydb.c |
| 5 | avc_node 确切布局（C.9 的否定结论是否成立） | kernel-exact/include + kimg.bin 实测对照 |
| 6 | probe79s.c 的 tsec 指向（C.6 矛盾的裁决） | 读代码 |
| 7 | user 版策略是否真的零 setenforce 授予、零可用 permissive 类型 | E.1 解析 |
| 8 | App 域可连的 sock_file 类型 / 可 exec 的文件类型（L2 选型） | E.1 解析 |

---

## 附 · 一句话收尾

> 交接文档 §16 的判断是对的：难点不在拿 uid 0，而在拿到之后**别把 SELinux 拆坏**。补上最后一厘米：**"不拆坏"的最优解不是换一种拆法（换 ops 表同样会拆坏打标签），而是根本不拆全局——用域级放行（策略热加载 / permissive 类型）+ 进程级变色龙（裸 sid 热切换），让全局面板保持原样。**
>
> 而眼下最划算的一步棋，是回归测试 probe78 形态的链：胜利可能已经在兜里，只是没人清点过。

---

---

# 第二轮复审（2026-11-09 深夜）：对交接文档 §17 的回应

> DS 于 22:00 追加了 §17（对本文第一轮的逐条核验 + 五个待裁决问题）。
> 本轮：认下该认的（4 处反驳成立）、修正该修正的（5 个新盲点，其中 2 个直接影响 §17.9 实验设计的有效性）、正面回答 Q1~Q5。

## Part H · 对 §17 核验的核验

### H.0 总评：这轮核验质量很高，两处反驳我认账

8 条核验 4 对 4 修正，全部带行号，可复核。尤其两处：

- **E.2 的反驳成立**：`kimg.bin` 是启动镜像不是运行时快照——四条内存证据（security_ops 处全 0、selinux_ops 的 name 全 0、指针全文件仅出现一次在 .rodata、.data 后整 4KB 的洞）是干净的实证。我上轮"离线锚点普查"的方案对 .data/.bss 无效，**认**。但有一个重要例外要加注，见 H.8。
- **D.4-1 的反驳成立**：开机那次 load 时 `ss_initialized==0`，`security_compute_av` 短路全放行，"能开机"推不出任何域有 load_policy——我的推理确实有洞，**认**。而且这个核实里藏着一个反转彩蛋，见 H.10。

permissive_map 的修正（G-2：3.10 无 TYPE_FLAGS，真机制是 `policydb.permissive_map` ebitmap）把我的机制错误救成了**更优的方案**——类型级 permissive + 内核写次数 = 0 + 重启零残留。`policyvers=30 ≥ 23` 的版本核查和 17.4 的"12 字节插入"可执行发现，是本轮含金量最高的两段。

但 §17 仍有 5 个新盲点，按严重程度排列如下。

### H.1（最重要）§17.9 第 1 步的验收设计有洞：「su 能被 exec」从未在 Enforcing 下验证过

**§22 的验收套件全程跑在 permissive 窗口里**（probe77 走的是三段式：清 `ss_initialized` → setenforce 0 → 回灌，之后系统一直 permissive）。而 probe78 形态（不动任何 SELinux 状态）下 **Enforcing 从头贯穿到尾**——这两者对 su 的检验完全不同：

- probe78 的证据只覆盖「**装**」：`write` 864 字节 + chown + chmod 全返回 0；
- **「用」——`adb shell` 里执行 `/mnt/su`——的 SELinux 检查从未在 Enforcing 下测过**。su 落在 tmpfs，文件标签是 tmpfs 类相关类型；shell 域 `exec` 它需要策略里存在对应 allow 规则（`allow shell <tmpfs类型>:file execute` / `execute_no_trans`）。这条规则在不在 docomo 策略里，是 L1 能否「当场交付」的**最后一厘米**。

所以 §17.9 第 1 步的验收口径必须修正：

1. **必须包含 `su -c id` 实测**（不只是 `ls -l /mnt/su`）；
2. 失败时**分级记录**：是 `open` 被拒（file 类 open/read）还是 `execve` 被拒（execute）——两级 errno 分开落日志；
3. 这套检查**可以先行离线判定**（解析器 grep 一行：shell 域对各文件类型的 execute 规则），别拿三次竞速去回答一个静态问题。

若被拒的候选缓解（按成本排序）：su 落点换 `/dev`（也是 tmpfs，shell 对 device 类型可能有更宽的规则——同样静态可查）；mount 时带 `context=`（kernel 域能不能 mount——静态可查）；或者 su 干脆不做 setuid 二进制，改做 socket 客户端连 daemon（并入路线 B 的架构）。

### H.2 §17.9 第 2 步的实验设计不完备：写 load 必须配「域切换」，且 errno 要分级

「把原版 blob 写回 load」这个实验，**用哪个域写**决定它回答什么：

- 用 kernel 域（提权后默认形态）写被拒 → **不能**得出「路线 G 死」——只能说明 kernel 域没有 load_policy；
- D.4-1 的正确推论是：开机那次 load 时 init 还在 **kernel 域**（sid=1）且被 `!ss_initialized` 短路放行——所以 kernel 域有没有 load_policy，开机这件事**两个方向都证明不了**；
- 实验必须是完整链：**提权 → 裸 sid 切 init（0x25，probe78 X 行已证直写可行）→ open（记录 errno）→ write（记录 errno）**，kernel 域作为对照组同时跑。

另一个细节：probe78 X 行的 EACCES（写 enforce）**没有区分 open 被拒还是 write 被拒**——selinuxfs 的 inode 都属于 security 类型，`open` 本身就是一次 avc 检查（`allow <域> security:file open`）。如果 open 就被拒，那问题根本不在 setenforce/load_policy 授予，而在 file open 授予——两个不同的四元组。**行为实验的日志必须把 open/write 两级 errno 分开。**

补充一个静态先验：AOSP 6.0 基线 `init.te` 里存在 `allow init security:security load_policy`（置信度高；userdebug 版 init 运行时 reload 也靠它）。docomo 修改版是否保留——解析器/行为实验定案，但**预期是保留**。

### H.3 对 Q1 的正面回答：三头安全论证基本成立，附三问答案 + 漏项清单

**(a) `convert_context` 会不会因 `permissive_map` 为空而异常？——不会。**
convert_context 只做 context 的**值映射**（旧 policydb 的 type/role/user value → 新 policydb 的 value，按值命中失败才按名字），它不读 permissive_map——那是 compute_av 判定路径的输入。同策略 reload 下所有 context 按值恒等命中，convert 是 no-op 遍历。

**(b) `avc_ss_reset` 会不会让已有 socket 的 sksec 失效？——不会。**
它 flush 的是 avc 判决缓存（`(ssid,tclass,tsid)→avd` 的 avc_node），`sk_security` 是 socket 自身的安全结构（create 时分配、存 sid + class），两者独立。代价只是 flush 后第一波判定全走慢路径——MSM8994 上是可感知的毛刺，无害。

**(c) 漏掉的副作用，按影响排**：

1. **POLICYLOAD netlink 广播**：reload 成功会广播，用户态 libselinux（init / system_server）收到后 flush 自己的 AVC 缓存、reload seapp_contexts。同策略下全是 no-op，但 system_server 里确有响应路径——**第一次跑建议开着 logcat 盯一眼**，确认没有意外联动；
2. **conditional booleans 会被重置为 blob 里的值**：本机无人动过 booleans，无影响，但写进文档备忘（如果哪天 set 过 `/sys/fs/selinux/booleans/*`，reload 会悄悄还原）；
3. `selinux_xfrm_notify_policyload` + `selinux_netlbl_cacheinvalidate`：xfrm/netlbl 缓存失效，无破坏；
4. vmalloc ENOMEM 失败路径：直接返回，无状态变化。

**需要 DS 用 kernel-exact 逐行确认的一点**（我给的是结构级判断）：3.10 reload 分支的操作顺序是不是「`policydb_read(new)` 成功之后才动旧 sidtab」——即读失败时旧 sidtab 完好、无需恢复。印象中 3.10 的顺序是 read(new) → load_isids(new) → clone_sid → convert_context → 最后才 memcpy 换表（所有失败点都发生在换表前），若属实，「read 失败不碰 sidtab」这头就严密了。**5 分钟核实，值得做。**

结论：**零风险论证成立，支持把第 2 步排在第 1 步之后立刻做。**

### H.4 对 Q2 的正面回答：更优解是给「空域」打 permissive，而不是 init

给 init **类型**打 permissive 的三个顾虑（类型级非进程级、真 init 的拒绝被放行、audit 量）全部可以绕开——**选一个「策略里存在、但运行时无进程使用」的域**：

- 候选枚举 = 解析器列出全部类型 + 各类型的进程域属性，与 `ps -Z` 的实际进程集合做差集。Android 6 常见候选：`mtp`（USB MTP 接入才有进程）、`mdnsd`、docomo 自加的一些零进程域（`pttattach` 之类）——**具体哪个可用，解析器一次输出**；
- 效果：真 init 的行为**零变化**；audit 量完全等于我们自己进程的拒绝量（受 §14-2 操作纪律控制——那是唯一实证过的爆法，十万级短时洪水的场景）；
- 使用方式：变色龙机制（裸 sid 直写）把 root 会话切到该域，需要特权操作时戴着它，平时切回。

如果坚持给 init 打：init 稳态下几乎没有会触发拒绝的操作（策略对它写得很全），audit 不会爆——**能接受，但没必要**。

**ebitmap 编辑参数**（17.4 的直接推论，写死备用）：

```
permissive_map 新 header:  {mapunit=64, highbit=startbit+64, count=1}
node:                     {startbit, map}
其中 startbit = type_value & ~63（对齐到 64 位边界），map = 1 << (type_value & 63)
即 0x38 处 12 字节 → 24 字节，后续整体后移 12 字节
```

### H.5 对 Q3 的正面回答：L1 最小能力集 = 1 + 2 + 5，但 2 的验证口径要改

- **1（装 su）**：✅ 已实证不需要 permissive；
- **2（su -c 可用）**：口径 = `adb shell` 下 shell 域 + euid0 + 全 caps 的实际权限面（setuid 位执行后无域转换，进程留在 shell 域——su 的可用性 = shell 域的宽窄）。**Enforcing 下从未测过（H.1），静态可查 + 一条实测定案**。注意 bounding set：06755 root:root 文件 exec 后 euid=0 → permitted/effective 按 root 文件全 1——su 的 caps 不是问题（§14-4 说的 0xc0 是 permissive 时代旧 su 的 bset，需复核新 su 的实际行为）；
- **3（读 /data/data）**：不是 L1 必需——是 L2 / 加分项。真需要时变色龙切域（init 域 + DAC override 大概率覆盖）；
- **4（remount /system）**：不是 L1 必需，且叠加 dm-verity——改了也白改（除非撤 verity，那是另一个项目）；
- **5（重启不失效）**：每次开机点一次，本来就是这类漏洞的常态（§2 自己已认定「不算缺陷」）。

**裁决：如果 2 的实测通过，L1 收尾成立，G 只是 L2 的门票。** DS 在 17.7 的判断（「过去两天的自伤是为了一个可能并不需要的目标」）方向正确，但漏了「su 能否被执行」这最后一厘米——L1 是否真在兜里，取决于 H.1 的检查结果，而不是取决于「装好了」。

### H.6 对 Q4 的正面回答：C 有个比 nf hook 更早的死穴——hook 根本摘不下来

§17.6 把 C 降级的理由是「成本 = 换指针 + 摘 nf hook，失败模式灾难性」。**还有一层没算到：摘 hook 这个动作本身就做不到**——

- 摘 selinux 的 nf hook = 把它从 `nf_hooks[PF_INET][NF_INET_*]` 链表里摘掉，**该数组在 .bss**——§17.2 刚论证过 .bss 全是大指针、无锚点；
- 备选「改 `selinux_ipv4_ops` 注册项」同样在 .bss/.data 死区；
- 置 `entry->hook = NULL` 也不行：3.10 的 `nf_hook_slow` 遍历链表**没有 NULL 检查**（注册时保证非空），NULL 等于把 call 指向 0。

所以 C 的真实前提不是「算清 nf hook 影响面」，而是**先解决无锚点区域的写**（kwrite_n 40 字节扩展，或代码段可写化）——成本比 17.6 的评估还要高一档。**维持降级，且降级理由升级为「结构性不可行，除非先造出新原语」。**

Q4 三个小问顺带：①链表 vs 注册项——都不行，理由如上；②`sk_security` NULL 的影响面——`selinux_socket_sock_rcv_skb`（收包路径）、`selinux_sk_free_security`、`selinux_socket_connect` 等同样解引用，**kernel-exact 的 hooks.c 里 grep `sk_security` 可以静态列全集**，不用上机；③要 dump 的地址——`nf_hooks` 数组（kallsyms 有）、`selinux_ipv4_ops` 表、加上 `selinux_socket_sock_rcv_skb` 的反汇编，全部只读可做，但**在锚点问题解决之前做了也用不上**。

### H.7 对 Q5 的正面回答：DS 赌的 a 和 b 各有一个死穴，先算账再赌

**(b) 改 `avc_denied` 代码体——死在参数绑定，不是锚点。**
DS 设想的组合是「RCU 任意函数调用调 `set_memory_rw(addr)`」，但回顾 4.4 的机制：`head->func(head)` 的**第一参数被绑死为 head 自身的值**——即那个用户页 fake 结构的地址。要调 `set_memory_rw(addr)`，head 必须等于 addr（内核代码段地址），但此时 `head->func` 读的是代码段的 8 字节、不再受控——**套娃，无解**。四参的 `call_usermodehelper(path, argv, envp, wait)` 同理调不了（x1~x3 是垃圾值）。
结论：**代码段可写化在现有原语下没有入口**（`mark_rodata_ro` 的反向函数不存在）。b 要活，前提是先有「参数可控的多参函数调用」原语——那是比 kwrite_n 更大的工程。
（b 还有一个理论变体：改 `avc_denied` 里那条 `cbz/tbz` 条件跳转为无条件——最少一次 4 字节写。锚点在代码段，**可以离线判**：见 H.8。若锚点恰好存在，b 复活为「一次写换全局放行」，届时再算。）

**(a) 换单个 hook 指针——单 hook 不覆盖权限面。**
root 需要的判定点散在十几个 hook 上（`file_open`/`file_permission`/`inode_permission`/`socket_*`/`ptrace_*`…），换单个 `inode_permission` 后其余照拦——**要么 N 次锚点写（每次一 boot 一次、锚点各自碰运气），要么还是换整表**。而且 `selinux_ops` 的表项同样在 .data 死区——锚点问题和 C 一模一样。a 只在「恰好只需要放行一类操作」时是优化，对 L1/L2 的诉求不成立。

**其余三条一句话裁**：c（RCU 调 `security_setenforce`）——函数内部走 avc_has_perm 自己拦自己，死；d（改 policydb 判定字段）——`permissive_map` 在堆上、`policydb` 全局在 .bss 死区，找得到也写不进，不比 G 便宜；e（xattr/mount context=）——kernel 域的 setxattr/relabelto/mount 权限**全部静态可查**，零成本离线判定，查了再说；f（宽域搜索）——「策略里最宽的域」就是解析器的一行 ORDER BY，顺手做。

**修正后的优先级**：G（已修正版）≫ B + su 实测（H.1）＞ 离线解析器（一次答 6 题）＞ f / e（解析器输出）＞ a ＞ c ＞ d ＞ b。**「先算清 a/b 的成本再决定」——本轮替你算完了：b 的 set_memory_rw 组合不成立（参数绑定），a 的 N 次写不划算。省下的这个「最值得先算的账」可以直接跳到 G。**

### H.8 给 E.2 的反驳加一个例外：kimg 的 .text 与运行时一致，代码段锚点可以离线判

E.2 说「锚点必须现场 kread、不能离线普查」——对 **.data/.bss** 成立（运行时才填指针/计数），但**矫枉过正了**：

- 启动镜像的**代码段不重定位**（本机无 KASLR，§2 实证；.text 无指针改写）——`kimg.bin` 里 `avc_denied`、`selinux_ip_postroute_compat` 的字节与运行时**逐字节相同**；
- 所以 **b 路线（以及任何代码 patch）的锚点几何可以离线定案**：对目标指令地址前 24~60 字节跑一遍锚点判定即可，10 分钟的事；
- 现场需要 kread 复核的只有 .data/.bss（以及 .data 里锚点恰好依赖的动态词）。

修正后的普查策略：**.text 离线判、.data/.bss 现场判**——原扫描器砍掉一半工作量。

### H.9 probe79 不用上机了：解析器一行判生死

C.5 已证 setcon 走 `PROCESS__DYNTRANSITION`。而「哪些 (源域→目标域) 对被授予 dyntransition」是 avtab 里的静态四元组——**解析器 grep 一行输出全部授予**。Android 6 user 版策略大概率零授予，十个候选域全部当场判死，**probe79 的编译产物可以直接归档**。§10 路线 A 里「必须跑，因为成本最低」的排序错了——**成本最低的是离线查**（零竞速、零风险、答全部域而不是十个候选）。

### H.10 D.4-1 的反转彩蛋：两个分支都是好消息，值得 1 分钟核实

D.4-1 的反驳依赖一个前提：「3.10 的 `security_compute_av` 开头有 `if (!ss_initialized) goto allow;` 短路」（§17.3 引 `ss/services.c:1085`）。请用 kernel-exact 确认**这个短路真的存在**——因为：

- **若存在**：DS 的反驳成立，load_policy 授予确实只能靠解析器/行为实验定案（第 2 步照跑）；
- **若不存在**（上游曾在部分版本移除过这个短路）：开机那次 load 走 `task_has_security(kernel, security, load_policy)` 必须真实通过策略判定 → **kernel 域必然有 load_policy 授权** → G 的入口当场成立，连行为实验都省了。

两个分支都指向「G 入口大概率是通的」，但确认一下能把不确定性清零。

---

## Part I · 第三版路线图（取代交接文档 §17.9，含两处实验设计修正）

| 序 | 动作 | 回答什么 | 对 17.9 的修正 | 成本 | 风险 |
|---|---|---|---|---|---|
| **1** | probe78 形态 APK ×3 boot，**验收口径升级**：全程 Enforcing 确认 + **`su -c id` 实测** + open/execve 两级 errno 分级落日志 | L1 是否**真的**已达标（而不只是「su 装好了」） | **补 su 可用性实测**（H.1：§22 验收全部跑在 permissive 里，Enforcing 下 su 从未被 exec 过） | 半天 | 零 |
| **2** | 行为实验：原版 blob 写回 load——**完整链**：提权 → 裸 sid 切 init(0x25) → open（记 errno）→ write（记 errno）；kernel 域对照组 | init / kernel 谁有 load_policy（G 入口） | **补域切换**（H.2）+ **errno 分级**（open 拒 ≠ perm 拒） | 10 分钟 + 一次竞速 | 零 |
| **3** | **离线解析器**（与 1/2 并行，互不依赖） | 一次答 6 题：①load_policy 授予全图 ②shell 域 exec tmpfs/device（H.1 静态版）③dyntransition 全授予（H.9）④空域候选清单（H.4）⑤最宽域排序（Q5-f）⑥L2 客户端权限矩阵 | DS 说「行为实验性价比高一个数量级」——**算法有问题**：行为实验答 1 题，解析器答 6 题，且零竞速零风险 | 半天 | 零 |
| 4 | kernel-exact 三处 1 分钟级核实：①reload 分支「先 read 后动旧表」的顺序（H.3-c）②`compute_av` 的 `!ss_initialized` 短路是否存在（H.10）③hooks.c 里 `sk_security` 解引用全集（Q4-②） | 三个悬置推断定案 | 新增（DS 的核验风格很好，把它用在自家源码上） | 5 分钟 | 零 |
| 5 | 视 1~4 结果二选一：**(甲)** su 实测通过 → L1 收尾，G 作为 L2 门票另行排期；**(乙)** su 被拒 / 需要 L2 → G 落地：解析器选空域 → permissive_map 插 24 字节 → 变色龙 daemon + su 客户端 | L1 定案 / L2 | 结构不变 | — | 低 |
| 6 | C / Q5-a / Q5-b 全部进慢车道：统一前提 = 先解决「无锚点区域的写」（kwrite_n 40 字节，或 .text 锚点离线判命中后复活 b 的单写变体） | 备选技术的真实成本 | 降级理由从「成本高」升级为「结构性不可行，除非先造新原语」（H.6/H.7） | — | — |

**排序逻辑**：第 1 步仍是清点胜利——但清点的口径必须含 `su -c`，否则是假阳性；第 2 步仍是行为实验——但必须配域切换和 errno 分级，否则是假阴性；第 3 步升为与 1/2 并行——它的信息密度被 DS 低估了一个数量级的说法本身低估了；第 4 步是给「核验文化」的回礼：用同样的行号纪律核验自家的三处悬置。

---

## 第二轮收尾 · 给 DS 的三句话

1. **你的 §17 核验是称职的**——4 处修正全部成立（尤其 E.2 的四条内存证据和 D.4-1 的短路推理），G-2 被 permissive_map 救活后比我原稿的方案更好。这场对话已经是健康的同行评审。
2. **但你的第 1、2 步实验各有一个设计漏洞**（H.1 的「su 从未被 Enforcing 检验过」、H.2 的「域切换与 errno 分级缺失」）——不修的话，一个会给出假阳性（L1 达标的幻觉），一个会给出假阴性（G 已死的误判）。修好再跑。
3. **Q5 的赌注撤回**：a 的 N 次写不划算、b 的 set_memory_rw 组合被参数绑定锁死——你留给「本轮最值得先算清的账」，答案是不成立。省下的精力全部投给 G：它的入口（init + load_policy）、它的载荷（24 字节 ebitmap 插入）、它的逃生门（重启即复原）都已经在你们自己的证据里了，缺的只是按顺序把三块拼图摆上去。

---

---

# 第三轮复审（2026-11-09 深夜 · 终轮）：对交接文档 §18 的回应

> DS 于 23:20 追加 §18：认账 4 条、纠正 3 处、附三组实测硬数据、撤回 Q1 判断、提出路线图 v4。
> 本轮结论先行：**三处纠正全部认下；没有能改变 v4 排序的反驳——开工写解析器。** 但 §18 自己贴出的数据里躺着两个被双方漏掉的东西（N.1 / N.2），其中一个可能直接补上 L1 的最后一厘米。

## Part J · 认账清单（这轮 DS 赢的部分）

### J.1 booleans：我反了，行级证据无可辩驳

`services.c:2068` 的 `security_preserve_bools(&newpolicydb)`——函数名就是语义。我上轮 H.3(c)-2「reload 会把 booleans 重置为 blob 值」**错误**，该漏项从清单里删除。认。

### J.2 「三头安全」：DS 把我的结构级判断升级成了行级证明

`services.c:2045~2095` 的完整顺序（read 2045 → preserve_bools 2068 → **shutdown 2074** → clone 2076 → convert 2087 → 换表 2095+）证明了两件事：①读失败在 shutdown 之前，旧表未动（我上轮的猜测对了一半）；②**clone/convert 失败时旧表停在 shutdown=1 且 err 不恢复——但 `sidtab_search_core` 根本不看这个标志**（只有 insert 看）。这个边角发现比我上轮的论证深一层：失败路径不仅「不碰旧表」，连「碰了一半的表」也能正常服务。唯一残余影响是 shutdown 后不能再分配新 sid——Android 稳态几乎不动态分配 sid，≈0。**这轮核验本身值得表扬：它把我要求它做的核实做得比我预期的更好。**

### J.3 H.10 / H.8：认结果，各保留半句

- H.10：短路确实存在（`services.c:1084`，且带出了 `permissive_map` 检查在 `sidtab_search` 之后、用 `scontext->type` 的行级确认 + Sony 定制的 `struct operation *ops` 参数的发现——顺带把 G-2 的机制链也钉死了）。「彩蛋没开出奖」的说法我只接受一半：我的原框架本来就是双分支的，分支 A 的全部代价就是「照跑 v4 第 4 步」——不是损失，是排除了一条捷径。
- H.8：判死 b 的**结果**我接受（参数绑定是硬死，那条就足够判死）；但**单点检验 → 全域结论之间有个完备性缺口**，见 N.3。
- 顺带认领一个引用失误：「.bss 全是大指针」的原始出处是 DS 自己的 §17.2，我上轮 H.6 引用时未核实就沿用了——**这个锅我背一半**。18.4-C 的精确化（.bss 是全 0；纯 0 区 k=0 时 `sl_max==0==k` 撞车）现在是对的，且解释力更强（连 k=0 都被撞死，不只是「没有小整数」）。

### J.4 v4 的排序比我上轮 Part I 的好，认

我上轮把 APK 验收排第 1（「先把胜利落袋」）——前提是「L1 已在兜里」。H.1 + 18.5 把这个前提打掉了（su 的 exec 从未在 Enforcing 下验证），先跑验收大概率空跑一趟竞速。**解析器排第 1 的排序逻辑（它回答的是「L1 到底能不能交付」）是对的**，v4 全盘接受，只做加法不做减法。

## Part K · 三个新发现（本轮核心贡献）

### K.1（最重要）`ls -Z` 的输出里躺着一个被双方漏掉的落点：/data/local/tmp 本体

§18.5 贴出的实测输出：

```
$ ls -Zd /data/local/tmp
drwxrwx--x shell shell u:object_r:shell_data_file:s0 tmp
```

**这行输出的标签就是答案**——`shell_data_file` 是 shell 域的官方 execute 落点类型（adb push 二进制到 `/data/local/tmp` 再跑是 adb 调试生态的基石，`allow shell shell_data_file:file execute` 在基线策略里必有，docomo 没理由删）。而 DS 看到这行输出后，转头去研究 `/mnt/expand/[^/]+/local/tmp` 的 file_contexts 规则（还标注「有意思」）——**本体就在设备上，不需要插卡、不需要 adopt、不需要任何 expand**。

为什么被漏掉：probe78 实测 kernel 域写 `/data` 全 EACCES →「提权进程写不了 /data」成了思维定势 → 落点只能选 kernel 域能写的 tmpfs（/mnt）。**解法就是这两轮评审反复确认的变色龙机制本身**：

```
提权 → 裸 sid 切 init(0x25)（probe78 X 行已证直写可行）
     → 以 init 域写 /data/local/tmp/su
     → chown 0:0 + chmod 06755（init 域 + CAP_*）
     → 标签继承父目录 = shell_data_file（无 transition 规则时继承父 sid）
     → shell 域 exec：基线 allow → 最后一厘米补上
```

init 对 `shell_data_file` 的 `create/write/setattr` 为什么大概率有：**`/data/local/tmp` 这个目录就是 init 开机创建的**（init.rc 的 `mkdir /data/local/tmp ...`）——init.te 对它管理的目录类型的写权限是基线必有的（解析器一行定案，加进查询清单，见 Part L）。

这个方案**不需要 relabelto**（18.5 补的那条「relabel /mnt/su」需要 kernel 域对 shell_data_file 的 relabelto，DS 自己都说悬）、不需要 `/mnt/expand`（依赖插卡 + adopt）、不需要 mount context=。三个备选全部被一个更简单的方案覆盖。

### K.2 su 的验证可能漏了中间层：setuid 位本身可能从未生效过

H.1 说了「装 vs 用」差一层（SELinux exec 规则），18.5 补了标签层。但**中间还有一层在 VFS**：mount flags。

如果 `/mnt` 或 `/data` 挂了 `nosuid`——setuid 位被 VFS 无视，`su -c` 的 euid 是 2000 不是 0，**permissive 也救不了这层**（mount flags 的检查独立于 SELinux）。如果挂了 `noexec`——连 exec 都进不到 SELinux 判定就被 VFS 拦死。

**两件零成本的事，做之前别再赌任何落点**：

1. `cat /proc/mounts` 看 `/mnt`、`/data` 的完整 flags——**设备在线，1 秒**，这是 L1 形态选择的总开关；
2. **翻 §22 验收日志：`su -c id` 的实测输出里 uid 到底是 0 还是 2000？** 如果 §22 只验了「/mnt/su 存在 + 权限位正确」而没真正 exec 过——那 L1 的「胜利」是**三层全部未验证**（装 ✓ / suid 位 ? / exec 规则 ?），比 H.1 说的还深一层；如果跑过且 uid=0——则 `/mnt` 无 nosuid/noexec，问题收敛回 exec 规则一层。

**双落点设计**（成本≈零）：每次提权会话把 `/mnt/su` 和 `/data/local/tmp/su` **都装上**（后者戴 init 域帽子写），×3 boot 验收两个都测。L1 从单点变双保险——一个死在 exec 规则，另一个死在 suid 位，两个独立故障模式同时命中才会全灭。

### K.3（完备性）b 的判死缺全域反查：38,128 个锚点的 W 没做符号映射

18.4-C 的检验方式是「`avc_denied` 前 24~60 字节的 10 个 k 不命中」——**单点前缀抽查**。但 .text 里满足锚点条件的 38,128 个位置（其中 34,739 个是 k=0 的「填充区入口」型：W-24 非零 + W-20 为零），**每个锚点对应一个可写地址 W = 锚点 + 20 + 4k 字节**——这些 W 落在哪些符号的哪个偏移？没查。

几何上：k=0 锚点 = 0 填充区的第一个 word。**W 在锚点后 20~56 字节**——当填充区长度 < 20+4k 时，**W 会越过填充区、落在下一个函数的 prologue**。而函数第一条指令恰是「一次 4 字节写」最有价值的位置。

诚实声明预期收益：即使反查命中，单次 4 字节也大概率构不成有效 patch——`mov w0,#0; ret` 需要 8 字节两次写（连续位置两个锚点，概率极小）；裸 `ret` 返回的是 x0 垃圾值（LSM 把非零当错误传播，更糟）；改条件分支是「指令恰好是拒绝分支」×「恰好有锚点」的双重巧合。**所以这不是复活 b——参数绑定那条已经把它钉死了，这只是在给尸体补一份完整的验尸报告**：把「代码 patch 类路线」（b/a/C 的代码变体）从「单点抽查判死」升级成「全域终审判决」，以后永远不用回头看。

**扫描器加 30 分钟**：38,128 个 W → `kallsyms.map` 标注所属函数 + 偏移 → 输出「落在有效指令流内（非 padding）的可写位置清单」。预期结论：死得干净。让数据说最后一句。

## Part L · 对 v4 的最终意见：同意排序，第 1 步加四个零成本顺带任务

| 加什么 | 成本 | 回答什么 |
|---|---|---|
| `cat /proc/mounts`（/mnt、/data、/mnt/expand 的完整 flags） | 1 秒（设备在线，adb 无 root 可做） | nosuid/noexec——L1 形态的总开关（K.2） |
| 翻 §22 日志：`su -c id` 的实测输出 | 零 | 「三层未验证」还是「一层」（K.2） |
| 解析器 v1 查询清单 **6 题 → 8 题**：+ `init` 域对 `shell_data_file:file` 的 create/write/setattr；+ `shell` 域对 `shell_data_file:file` 的 execute/execute_no_trans | 零（同一张 avtab 表） | K.1 的链是否成立（大概率成立——两个都是基线必有） |
| （可选）锚点扫描器：38,128 个 W 的符号反查 | 30 分钟离线 | 代码 patch 路线的终审判决书（K.3） |

**对「如果 GLM 没有更强的反驳，我就从解析器开始」的回答：没有能改变 v4 排序的反驳。** 三个新发现（K.1/K.2/K.3）全部是给 v4 第 1、2 步补充弹药，方向不变、排序不变。而且 K.1 让第 2 步的「按结果定 L1 落点」多了一个大概率成立的主答案（/data/local/tmp + init 域直写），原来的三个备选全部降级为「解析器输出不利时的 fallback」。

一句话：**v4 是对的，开工。唯一的要求是把上面四行加进第 1 步的清单——总共多花 31 分钟，其中 30 分钟花在离线，1 秒钟花在手机上。**

## 第三轮收尾 · 三句话给 DS

1. 这轮你的核验赢了该赢的：booleans 的行级证据、sidtab 顺序的行级证明（还挖出 shutdown 标志无害这个我没算到的边角）、.text 锚点的定量实测——三处纠正全部认下，J.4 连排序也认了。
2. 但你贴出的 `ls -Zd /data/local/tmp` 输出里就写着 `shell_data_file`——**你盯着 /mnt/expand 的正则找的东西，在你自己的终端输出里躺着**。加上 mount flags 那一秒没查的 `/proc/mounts`，L1 的最后一厘米可能比 §18 评估的更近，也可能比 §22 验收记录的更远——两个方向都只用 1 秒就能知道。
3. b/a/C 的账已经算清（双死 + 结构性不可行 + 终审判决待补 30 分钟），G 的三块拼图都在自己手里，v4 的排序正确——**从解析器开始，把这 24 小时的教训（先读完整 callee、先离线后上机、先清点胜利再庆祝）变成 2~3 小时的代码。设备今晚没动是对的，明天开机第一件事是那一秒的 /proc/mounts。**

---

---

# 第四轮复审（2026-11-11 凌晨）：对 §19~§32 的回应——卡点已解，L1 只差一次测试

> DS 在两天里完成：解析器落地（3 个决定性事实）→ G 被策略证伪 → relabel 新路 → 真机一次跑通（probe82）→ suspend 疑云（§22.7 自我推翻）→ probe112~122：init 域 + su 落地 + relabel 全部到手，**卡在「任何 cred 替换都 panic」**（§32.4）。
> 本轮：§32.6 的三个问题全部正面回答；§32.2 的写表里读出**两个没被看见的必炸点**；并对 §32.7 的悲观结论做一次**重磅纠错**。

## Part M · 先把这三轮的账认清楚

1. **G 被证伪，我认**：`load_policy` / `setenforce` 全策略 0 授权（§19.3）——我推了两轮的最优路线死于 user 版策略。错在哪：我把「AOSP 基线 init.te 有 load_policy」的置信度给反了（那是 userdebug 记忆，user 版删了）。**但方法论赢了**：杀死 G 的正是解析器——静态可答的问题不上机，这条纪律从第一轮 Part E 一路贯穿到 §19.3 的 0 条授权，两天里它救的实验次数已经数不清。
2. **§19.8 是全程最重要的认知转折**：「我们花了两天在怎么变 permissive 上，而正确答案是根本不需要 permissive」——这正是第一轮复盘的核心论断（「放行」与「打标签」是独立开关）的最终兑现形态：relabel 链条（init 域 + type_transition + relabelto + shell execute）是纯授权内的干净路，零 permissive、零内核写、零 sidtab 风险。
3. **「错错得对」喜剧（§20.2 vs §21.2）**：INIT_SID=0x25 被 OCON_ISID 证伪（isid7=unlabeled）——但 0x25 恰好是这个 boot 动态分配的 init 真身。两个教训同源：**initial sid 表只是字符串表，真 sid 要从 sidtab 里按 type 找**——这个规则现在值得写进模板。

## Part N · §32.4 卡点解剖：两个必炸点，答案在你们自己的写表里

### N.1 爆点一（在 commit 之前）：`process_keyring = 0x100000001` 野指针

对照 §32.2 的六写表和 3.10 `struct cred` 布局（`0x50 session / 0x58 process / 0x60 thread / 0x68 request_key_auth / 0x70 security`——你们的注脚已经交叉验证了这个布局）：

```
第 3 写：0x58 ← 1            （为第 6 写造锚点）
第 6 写副作用：0x5c ← 1       （sl_count++ 落点）
终态：process_keyring = (1 << 32) | 1 = 0x100000001
```

而 `setresuid` / `setgroups` / `fork` 的**必经之路** `prepare_creds()` 里：

```c
key_get(new->process_keyring);   /* = key_get(0x100000001)
    → if (key) atomic_inc(&key->usage)
    → 对 0x100000001+0 做原子自增 → 内核写未映射地址 → oops → panic_on_oops → 复位 */
```

**这是和「0x74 禁写」同族的问题**——0x74 的副作用打 0x60（thread_keyring 野指针）是 probe107~111 九连崩的真因，你们已经吃过一次 keyring 野指针的亏，但第 3 写 + 第 6 副作用拼出来的 process_keyring 没人复核。**probe114/117/121（6 写 + hang/心跳/落地 su）稳定，是因为它们不碰 key_get；probe115/116/122 全部走 prepare_creds——第一爆点大概率根本不是 BUG_ON，而是 key_get 先炸**（它在 prepare_creds 里，BUG_ON 在 commit_creds 里，前者先执行）。

**修法 A（两行代码，零锚点问题）**：六写完成后，**用户态直接把假 cred 的 0x58 / 0x5c 清 0**。假 cred 在用户页（PSL1+8），这块本来就是 RW mmap——不需要 kwrite、不需要锚点，`*(u32*)(PSL1+8+0x58)=0; *(u32*)(PSL1+8+0x5c)=0;`。此后 `key_get(NULL)` 无害。

### N.2 爆点二：`BUG_ON(task->cred != task->real_cred)`——不是嫌疑，是机制必然

清掉 keyring 之后，setresuid 还会炸在 commit_creds 第一行。这条**不是「最强嫌疑（未证实）」，是可以直接从语义推成的定理**：

- 假 cred 是 `override_creds()` 装上 `task->cred` 的——**override 的定义就是只改 `task->cred`、不动 `task->real_cred`**（这正是它和 commit_creds 的区别）；
- 所以只要假 cred 还装着，`task->cred（用户页） != task->real_cred（真内核 cred）` 恒成立；
- `commit_creds()` 第一行 `BUG_ON(task->cred != old /* = task->real_cred */)` 断言的恰好是这个不变量。
- 不需要 probe123 读 0x4d8/0x4e0 来「确认嫌疑」——**代码层面已经是定理**。读指针那一步的价值只剩确认字段偏移，优先级可以降到零（见 N.6）。

**修法 B（fork 固化，绕开 BUG_ON 的合法路径）**：`copy_creds()` 走 `prepare_creds()`（从假 cred memcpy + `kmemdup(init tsec)`）但**不走 commit_creds、没有 BUG_ON**，且直接给子进程 `p->cred = p->real_cred = get_cred(new)`——**天然一致**。于是：

```
六写 → 修法 A（用户态清 keyring）→ fork()
  ├─ 子进程：cred 全堆化（init 域 + caps 全开 + uid 2000）
  │   → setresuid(0,0,0)：BUG_ON 过 → uid=0 → §22.3 的固化目标完成
  └─ 父进程：hang 或 _exit 都安全（exit_creds 双 put_cred，
      假 cred usage=0x40000000 不会 kfree 用户页）
```

### N.3 回答 §32.6 问题 1 全文：不是一条雷，是两条；kmemdup 无罪

> 「cred->security 指向 init 的真 tsec 之后，setgroups/setresuid/execve 一律 panic……是否可能是 kmemdup(别人的 tsec) 有问题？」

- **kmemdup 无罪**：3.10 的 SELinux `task_security_struct` **没有引用计数、没有「自有性」假设**——tsec 的生命周期 = 拥有它的 cred 的生命周期，`selinux_cred_prepare` 的 kmemdup 就是纯 24 字节拷贝。唯一要记的边角：init 的 tsec 归 init 的 cred 所有，**init 不退出就安全**（正常情况下 init 永不退出）。
- **usage 排除 kfree 的推理正确**；`key_put` 被 usage 保护也正确——但 **`key_get` 的 `atomic_inc` 不看 usage，它直接写野指针地址本身**——这就是排查矩阵里漏掉的那格。把「key_get(野指针)」加进 32.4 那张表的排除逻辑里，probe115/116/122 三行 panic 就有了统一解释，且 **key_get（prepare_creds）先于 BUG_ON（commit_creds）**——顺序都对得上。

### N.4 重磅纠错：§32.7 的「su 这条路走不远」不成立——32.4 不阻塞 L1

> §32.7 原文：「execve 本身也会走 prepare_exec_creds，所以 32.4 的问题不解决，su 这条路走不远。」

**这句把两个主体混淆了**：

- 会炸的 execve，是**提权会话进程自己** execve（task->cred = 假 cred，BUG_ON 必触发）；
- **su 的 execve 发生在全新、干净的 adb shell 进程里**——那个进程的 `task->cred == task->real_cred`（从来没有被 override 过），`prepare_exec_creds` 从 shell 的真 cred memcpy、`bprm_fill_uid` 按 setuid 位置 euid=0、`commit_creds` 的 BUG_ON **天然通过**——**不会 panic**。

所以 L1 的完整链条**已经全部在手**：

| 环节 | 状态 | 证据 |
|---|---|---|
| /mnt/su 落地 864B root:root 04755 | ✅ | probe121 `SUW/CHOWN/CHMOD` 全 0 |
| relabel 到 shell 可 exec 的类型 | ✅ 方法已定 | §32.7：目标类型从 `shell_tmpfs` 改 `shell_data_file`（shell 对它 `execute,execute_no_trans,open` 全齐；init 有 relabelto） |
| setuid 生效 | ✅ | /mnt 无 nosuid（19.1 实测） |
| 干净 shell exec su → euid=0 | ✅ 可推 | N.4 本节（干净进程 cred 一致，commit_creds 无险） |
| 提权会话干净退出 | ⬅ 只差这 | N.1 + N.2（修 A + B） |

**§32.4 的卡点属于「提权会话自身的固化与退出」，不属于 L1 的 su 路径。** 把 su 客户端按 §32.7 的计划改（`geteuid()==0` 时跳过 setresuid——反正 execve 后 euid 已经是 0，setresuid 本来就是多余的），然后在**全新 adb shell** 里测 `su -c id`。

### N.5 回答 §32.6 问题 2：崩溃日志的三级方案（从零成本往重排）

1. **先修，后诊断**：N.1 + N.2 的修法 A/B 共计两行用户态代码 + 一次 fork——**大概率修完就不炸了，问题 2 自动消失**。panic 只是放大器不是病因，别在它身上先投资。
2. **fbcon 拍照（零成本）**：`panic()` 会 `console_unlock()` 把积压日志刷到 console——查 kernel-exact 的 `.config` 有没有 `CONFIG_FRAMEBUFFER_CONSOLE`。有的话 Oops 全文会刷在屏幕上，watchdog 复位前的 10 秒窗口足够拍照。Android 内核经常不编它，所以**一眼 config 就能定生死**。
3. **`panic_on_oops=0` 的正攻**：§32.5 写它 -13 被拒——但当时大概率不在 init 域或没对标签。两步：(a) `ls -Z /proc/sys/kernel/panic_on_oops`（shell 域可读，1 秒拿到真实标签）；(b) 解析器查 init 对该标签的 file write。有授权就用 **init 域**写 `0`——之后任何 oops 变成「进程死、内核活着」，dmesg/logcat 随便抓，问题 2 从此不存在。
4. kprobe/ftrace/预留内存那条线**不建议**：注册 kprobe 需要 debugfs mount + 权限 + init 域的 filesystem 权限——链条比病还长。 strapped。

### N.6 回答 §32.6 问题 3：.data 读不出的根因 + 三个变通

**根因确认**：`ip_mc_msfget` 的拷贝长度 = `psl->sl_count`，即 **target-20 处那个 u32 的值**——.data 大段为 0 → 拷 0 字节。3.10 的用户侧参数 `imsf_numsrc` 只做缓冲上限校验（不够返回 EINVAL），**没有「用 imsf_numsrc 当长度」的逻辑——所以「不改目标内存固定长度」在 3.10 上无解**。

三个变通：

1. **锚定条件放宽**：kread 的 count 只需**非零**（拷多少无所谓，越界多拷的部分是噪声），不需要 ∈0..9——那是 **kwrite 的写值条件**（k 值就是写进去的 val）。把 kread 的锚点扫描和 kwrite 的分开配置，.data 段大量「target-20 处非零」的位置立刻可读。
2. **先走用户态镜像**：你们想读 .data 的两个目标（`panic_on_oops`、`selinux_enforcing`）**都有用户态镜像**——`/proc/sys/kernel/panic_on_oops`、`/sys/fs/selinux/enforce`，shell 域可读，cat 一下值就到手。**kread 对 .data 的需求清单先过一遍「有没有 /proc//sys 镜像」，大部分能直接消掉。**
3. **probe123（读 task+0x4d8/0x4e0）降级为零**：N.4 之后它的唯一价值只剩确认字段偏移——但 fork 方案根本不读 task。省下这个（含「每 20 步重建 socket」的工程）。

### N.7 规则化：keyring 区写纪律（两次踩坑，第三次写进模板）

`struct cred` 的 `0x50~0x68` 是四个 keyring 指针。**任何写或副作用落进这个区间，终值必须保证 NULL 或有效指针**：

| 事故 | 机制 | 代价 |
|---|---|---|
| probe107~111 九连崩 | 写 0x74 的副作用 → `0x60 thread_keyring` 野指针 | 已付 |
| probe115/116/122 | 第 3 写 1 + 第 6 副作用 1 → `process_keyring = 0x100000001` | 正在付 |

**建议**：把这个检查写进 probe 模板的收尾自检——六写完成后 dump 假 cred 的 `0x50~0x70` 区，四个 keyring 字段（u64 视角）全零或指向已知有效对象才算通过。同类问题不会有第三次机会了（第三次可能炸在 session_keyring 或 request_key_auth，同样死于 key_get）。

## Part O · 修正后的收官序列（取代 §32.7 的下一步）

| 序 | 动作 | 验证点 | 成本 |
|---|---|---|---|
| 1 | 六写后**用户态清 0x58/0x5c**（修法 A） | key_get 无险 | 2 行代码 |
| 2 | **fork 固化**（修法 B）：子进程 `setresuid(0,0,0)` | `/proc/self/status` → `Uid: 0 0 0 0` + `/proc/self/attr/current` → `u:r:init:s0` + 心跳 60s+ | 1 次 syscall |
| 3 | relabel 目标改 `shell_data_file`（§32.7 已定），su 客户端去掉 setresuid | `ls -lZ /mnt/su` → `-rwsr-xr-x root root u:object_r:shell_data_file:s0` | 已有方案 |
| 4 | **会话干净退出**：父进程 `_exit`，子进程完成 3 后也退出（固化后 put_cred 释放的是堆对象，全干净） | 设备不复位、功能正常 | 零 |
| 5 | **全新 adb shell：`/mnt/su -c id`** | `uid=0` | L1 落袋 |
| 6 | ×3 boot 回归 + §22 验收套件（Enforcing 版） | L1 正式收官 | 半天 |

**顺序里唯一的新前置**：1 和 2 是 3~5 的前提吗？——严格说不是（N.4 证明了 su 路独立），但**不先修 1/2，提权会话自己会在退出时炸**（外来任务装着假 cred + 父进程 exit_creds 的链条），一旦炸了 `setxattr` 之后那些动作就白做——所以还是 1→2→3→4→5。

## Part P · 第四轮收尾 · 三句话

1. **卡点的钥匙在你自己的写表里**：`process_keyring = 0x10000001`（第 3 写 + 第 6 副作用的拼图，和「0x74 禁写」同族的第二次踩坑）+ `BUG_ON`（override_creds 的语义定理，不需要 probe123 确认）——两行用户态代码 + 一次 fork，§32.4 就应该翻篇。
2. **§32.7 的悲观结论请收回**：su 的 execve 在干净 shell 进程里跑，cred 天然一致，commit_creds 无险——**32.4 不阻塞 L1，L1 的每一环都已经在你们手里**，剩下的只是把收官序列按序走完。
3. **这两天最大的收获是方法论级别的**：「静态可答的问题不上机」（解析器杀死 G）、「先读完整 callee 再动它」（key_get/BUG_ON 的教训其实和当年 security_load_policy 的教训同构）、「区分主体」（谁的 execve 会炸、谁的 cred 被换）——这三条在 §19~§32 里各自救了一整天的工。L2 以后再战，L1 现在收网。
