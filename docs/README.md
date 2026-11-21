# 文档地图

这个仓库记录一台 **Sony Xperia Z5 / SO-01H（docomo, sumire, MSM8994, Android 6.0.1, 32.1.F.1.98）**
的 root 与 bootloader 解锁研究。三条线索并行，性质完全不同，读文档时不要混为一谈：

| 线索 | 目标 | 结局 | 权威文档 |
|---|---|---|---|
| **A. 内核提权** | 拿到 uid=0 | ✅ 成功，做成可分发 APK | [`research/root-lpe-attack-surface.md`](research/root-lpe-attack-surface.md) + [`research/root-retrospective.md`](research/root-retrospective.md) |
| **B. BL 解锁** | 解锁 bootloader | ❌ 判定不可行（缺 S1 根私钥） | [`research/bl-conclusions.md`](research/bl-conclusions.md) |
| **C. 免解锁降级刷机** | 刷 2016 老固件换 Dirty COW | ⛔ 放弃（缺 FTF，且被 A 取代） | [`research/legacy-readme-downgrade-route.md`](research/legacy-readme-downgrade-route.md) |

## 先读什么

新接手（人或 agent），按这个顺序，40 分钟能建立完整认知：

1. [`../AGENTS.md`](../AGENTS.md) —— 工程纪律与目录职责（**先看这个**）
2. [`status.md`](status.md) —— 一页现状：设备状态、已判死的路、下一步
3. [`timeline.md`](timeline.md) —— 八轮迭代（R0~R7）的编年史，含每次转向的原因
4. [`pitfalls.md`](pitfalls.md) —— 踩过的坑，**动手前必读**，能省你一天
5. [`decisions/`](decisions/) —— 每个"不做了"背后的取舍（10 条 ADR）
6. [`probes.md`](probes.md) —— 171 个探针的谱系：失败版本源码已删，为什么死都记在这
7. 需要细节时再查 `research/` 下的长文

## 目录职责

```
docs/
├── README.md        本文件：地图 + 权威性规则
├── status.md        当前状态（唯一"现在时"的文档，会持续更新）
├── timeline.md      迭代史（按轮次，只追加不改写）
├── pitfalls.md      踩坑清单（按类别，可续写）
├── glossary.md      术语表：TA / SIN / S1_* / verity / aboot 缩写都在这里
├── probes.md        探针谱系（失败版本索引；源码只留最终 4 份）
├── decisions/       架构决策记录（ADR），一条决策一个文件，编号递增
├── guides/          可执行的操作手册（构建、复现、设备通道）
├── research/        技术长文（原始结论层，带版本号与时效标记）
└── history/         原始会话与工作日志（史料，不保证准确，不修改）
```

## 权威性规则（重要）

历史上这批文档经过 v1→v11 反复修订，**同一件事在不同文件里可能有互相矛盾的表述**。
按下面的规则判断"信哪个"：

1. **`research/bl-conclusions.md` 是 BL 线索的唯一权威**（v11）。`bl-exploration.md` 是过程记录，
   里面被推翻的段落**保留原文不删**，靠 `§x.x 已被 §y.y 推翻` 的标记指向新结论。
2. **`research/root-lpe-attack-surface.md` 是提权攻击面的权威**（2026-11-07 版），
   但其中"当前主攻方向"一节描述的是**当时**的进度，最终形态见 `root-retrospective.md` 的 Part O 与 APK 本身。
3. **`docs/history/` 里的一切都不作数**——那是给"为什么当时这么想"留的证据。
4. 本目录下的 `status.md` / `pitfalls.md` / `decisions/` 是**后写的总结层**，
   如果它们和长文冲突，以长文中的【实测】证据为准，并**回来修正总结层**。

## 可信度标记

长文统一使用三档标记，不要混用：

- **【实测】** —— 设备上跑过，有可复现命令与对照
- **【强推断】** —— 反汇编 + 语义自洽，缺一步动态验证
- **【推测】** —— 待验证，不得作为决策依据

## 维护约定

- 新增一轮工作：在 `timeline.md` **追加**一节（编号顺延），不要改写旧节。
- 新增一个"决定不做 X"：在 `decisions/` 加一个 ADR，旧的 ADR 不删，用 `superseded by` 标注。
- 新踩一个坑：加进 `pitfalls.md` 对应类别，写清"症状 → 根因 → 判据"三段。
- 结论有变：先改 `research/` 长文并升版本号，再同步 `status.md`。
