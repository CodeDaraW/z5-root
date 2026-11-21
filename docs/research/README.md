# 技术长文索引

这些是**原始研究产物**，写作时间跨度 2026-11-07 → 11-13。带版本号，含大量被后续推翻的段落——
不要直接当"现在的事实"用，先看下面的权威性标注。

| 文件 | 写作时间 | 内容 | 权威性 |
|---|---|---|---|
| [`bl-conclusions.md`](bl-conclusions.md) | 11-13，**v11** | BL 解锁的结论层：六步证据链、路线判定表、复现清单、官方路径还原、收费工具机制 | ⭐ **BL 线索唯一权威** |
| [`bl-exploration.md`](bl-exploration.md) | 11-13，**v11 过程版** | 同一批工作的过程记录：每轮实验、反汇编细节、被推翻的假设都留着 | 过程层，只追加 |
| [`bl-review.md`](bl-review.md) | 11-11 ~ 11-13 | 第二模型（GLM）的对抗评审四轮，含 verity 布局破译、三件套双调用者等关键新事实 | 与结论层同等可信（其结论已被复核采纳） |
| [`bl-export-and-analysis.md`](bl-export-and-analysis.md) | 11-11 | 21 个分区 dump 的第一轮分析：TA 未加密、aboot 字符串、cmdline 泄漏、TA 易变性 | ⚠️ **v1 视角，部分归因已证伪**（文件头有提示） |
| [`root-lpe-attack-surface.md`](root-lpe-attack-surface.md) | 11-07 | 内核提权攻击面全清单：可达性表、KGSL 判死、Phoenix Talon 触发链、已排除路线 | ⭐ **攻击面权威**；"当前主攻方向"一节是当时进度 |
| [`root-retrospective.md`](root-retrospective.md) | 11-09 ~ 11-11 | 外部复盘四轮：三次弯路、L1/L2 拆分、路线 G 兴衰、Part N/O 的收官序列 | ⭐ 提权线索的**结论与教训**权威 |
| [`legacy-readme-downgrade-route.md`](legacy-readme-downgrade-route.md) | 11-07 | 最初的"免解锁降级刷 Dirty COW"方案记录 | 历史存档，路线已放弃（ADR 0002） |

## 怎么读

- **只要结论** → `../status.md` + `bl-conclusions.md` §0/§3/§11。
- **要动手复现** → `../guides/reproduce.md`。
- **要理解为什么放弃** → `../decisions/`（10 条 ADR）。
- **要取证**（某个地址、某条指令）→ 上面两张长文，用 `grep` 找地址/`0x` 前缀。

## 命名对照

整理仓库时做过重命名（内容未改）：

| 原名 | 现名 |
|---|---|
| `ATTACK_SURFACE.md` | `root-lpe-attack-surface.md` |
| `Z5-Root-复盘与路线建议.md` | `root-retrospective.md` |
| `BL-导出与分析.md` | `bl-export-and-analysis.md` |
| `BL-解锁探索.md` | `bl-exploration.md` |
| `BL-解锁结论.md` | `bl-conclusions.md` |
| `BL-解锁探索-review.md` | `bl-review.md` |
| `README.md`（旧） | `legacy-readme-downgrade-route.md` |

## 路径对照

长文正文里的路径是**写作当时**的，内容未改。照下表换算到当前布局：

| 文中旧路径 | 当前位置 |
|---|---|
| `bl/bl/`（除 TA.img） | `artifacts/bootloader/` |
| `bl/bl/TA.img` | `artifacts/ta/TA.img` |
| `bl/backup/` | `artifacts/ta/backup/` |
| `bl/vf/`、`bl/sys_*.bin`、`bl/p44_*.bin` | `artifacts/verity/` |
| `dump/` | `artifacts/device/partitions/` |
| `report/` | `artifacts/reports/` |
| `exploit/probe/` | `analysis/probes/device/` |
| `apk/`、`apk2/` | `apps/z5root/`、`apps/sutest/` |
| `tools/*.py`（TA/策略分析） | `analysis/ta/`、`analysis/selinux/` |

## 记号约定

- 【实测】/【强推断】/【推测】三档可信度，见 `../README.md`。
- `§x.y` 指同文件章节；跨文件引用会写文件名。
- 反汇编地址一律写 `0x3E0xxxxx`（aboot 基址 `0x3E000000`）。
