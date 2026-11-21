# 0001 · 只做临时 root，不追求持久化

- **状态**：已采纳（2026-11-10）
- **相关**：`../research/bl-exploration.md` §8、`../status.md`

## 背景

拿到内核提权后，最自然的目标是"重启后仍然有 root"。两条持久化路径都试过并被封死：

1. **改 `/system`**（放 su / 改 build.prop）。三堵墙：`MNT_LOCK_READONLY`（任何带 rw 的 remount 都 EPERM）、
   块层只读（`BLKROSET` 可清，但没用）、**dm-verity 已启用**（四证据）。
   verity 的信任锚 `/verity_key` 在**已签名的 boot.img** 里，改不了。
2. **改 boot.img 关 verity**。锁 BL 下不能刷 boot 分区，只能刷索尼签名的官方固件。

## 决定

接受 **临时 root**：每次开机后跑一次 APK，su 落在 `/mnt/su`（tmpfs），重启即消失。
把它做成"一键 + 自动重试 + 崩溃续跑"，把不便降到可接受。

## 后果

- ✅ 干净的失效语义：重启后 SELinux 回 `Enforcing`、`panic_on_oops` 回 1、`/mnt/su` 消失，
  **不需要任何卸载动作**。`/data/local/su` 残留无害（守护进程不在就明确拒绝）。
- ✅ 不必为"改 /system 变砖"承担风险。
- ⚠️ root 在位期间 SELinux 是 Permissive（全局），这是提权的必要前提。
- ⚠️ root 在位期间 `panic_on_oops` 保持 0（故意不恢复：UAF 现场一直挂着，
  恢复成 1 会让"日后再碰一下"直接重启；留在 0 最多杀一个进程）。
- ⚠️ 不要手动 `kill` 名为 `z5root` 的进程——它持着 UAF socket，退出可能 panic。

## 被什么推翻会重启这个决策

如果 BL 解锁成功（需要 S1 私钥或 docomo 官方渠道），持久化重新变成可选项。
