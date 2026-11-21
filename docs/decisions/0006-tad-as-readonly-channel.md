# 0006 · 把 TAD socket 作为无 root 的只读通道

- **状态**：已采用（2026-11-12）
- **相关**：`../../analysis/ta/tadif.py`、`../research/bl-exploration.md` §15.4

## 背景

TA 分析的瓶颈一直是"读不到"。有 root 时可以 `dd` 整盘，但 root 是临时的、还会崩溃重启；
很多验证（例如"设备上的 unit 内容与 dump 是否一致"）需要**反复、轻量、随时**可做。

## 发现

`/dev/socket/tad` 的属组是 `trimarea`(2993)，而 **`adbd` 就在这个组里**。于是：

```
adb forward tcp:19999 localfilesystem:/dev/socket/tad
```

即可在**完全无 root** 的状态下与 TA 守护进程通信。协议（私有，全大端）：

```
请求: [u32 len+9][u8 ver=1][u32 a0][u32 op][payload]
  op 0=open(payload=[mode,1])  2=getsize  3=read  4=write
回包: [u32 total][body]
  getsize body = [status][size]     read body = [status][len][data]
```

## 决定

把 `tad` 作为**默认的只读通道**，客户端固定为 `analysis/ta/tadif.py`；
所有需要"设备侧真值"的验证都走它，不再为了读 TA 去要 root。

## 后果

- ✅ 1962 个 unit 的全量逐字节比对只花约 1 分钟，不需要 root 窗口。
- ✅ 附带成果：证明 `ta_parse2.py` 的 `[uid][size][magic][flags]` 布局对**全量**记录成立
  （尺寸 100% 一致、内容 0 差异），这是记录格式从【强推断】升为【实测】的关键。
- ⚠️ **可见性过滤**：服务端对安全 unit 返回 `Unit not found(4)`（不是 `Operation not allowed`），
  所以"读不到"≠"不存在"。108 个被拒 unit 清单在 `../../artifacts/ta/security_units.txt`。
- ⚠️ **协议坑**：`ver` 必须为 1（否则 `Request format error [457]`）；`open` 的 `mode` 必须为 1；
  回包必须按 `total` 驱动解析，按固定长度读会流错位（早期"扫描无结果"就是这么来的）。
- ⚠️ `op=4`（write）**从未测试**，属于 ADR 0005 的禁区。想测必须先有恢复链。
