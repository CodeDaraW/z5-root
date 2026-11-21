# 0009 · 设备数据不入库

- **状态**：已采纳（2026-11-21，整理仓库时）
- **相关**：`../../.gitignore`、`../../artifacts/README.md`

## 背景

仓库里的 `artifacts/` 有 100MB+ 的设备导出数据，其中：

- `TA.img` 含 **IMEI**（6 处分块出现）、DRM keys、运营商配置（CDA/OP_NAME/HOP_ID）、
  以及 27 张 Sony X.509 证书；
- 21 个分区镜像含机器唯一标识与专有固件内容；
- `kimg.bin` / `kallsyms` 是这台机器的完整内核内存布局。

这些一旦进 git，就会永久留在 history 里（即使后续删除）。

## 决定

`.gitignore` 排除 `artifacts/**`（仅保留 `artifacts/README.md` 作为清单），
并同时排除 `vendor/`（第三方源码树，765MB）与 `tools/jdk17|sdk`（离线工具链，460MB）。

## 后果

- ✅ 仓库保持可克隆、可审计；不会有密钥材料或机器标识泄漏。
- ⚠️ 新克隆的仓库**跑不了**需要数据的脚本。解决办法：`artifacts/README.md` 里逐项写明
  "这个文件是什么、怎么从设备重新生成"（`scripts/device/bl_dump.sh`、`tadif.py`、离线探针）。
- ⚠️ 设备若已丢失或已还原，这些数据**无法重建**。因此在仓库之外必须有一份备份。
  **不要上传公有云**（TA 含 IMEI/DRM keys）。具体介质见下文"未解决的"。

## 未解决的

异地备份。`artifacts/` 是唯一副本，丢了不可重建。建议：加密压缩后放离线介质，
密码与数据分离保存。
