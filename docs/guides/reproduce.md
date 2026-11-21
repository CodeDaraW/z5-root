# 复现清单

两类：**离线**（只用手里的 dump，零风险，任何机器可跑）、**在线**（需要设备）。

设备数据不在 git 里（ADR 0009）。★ = 这项要先自己 dump 出文件，缺什么见下表。

---

## 每项要什么输入

设备数据一律不入库（ADR 0009），所以下表是「拿到仓库之后还缺什么」：

| 项 | 需要的文件 | 从哪来 |
|---|---|---|
| A TA 结构 | `artifacts/ta/TA.img` | 有 root 就 `dd` 整盘（device-access §3）；否则用 `tad` 全量读 |
| B bootconfig | `artifacts/ta/bootcfg_84f.bin` | 从 `TA.img` 取出 unit `0x84F` 的 97 字节（`ta_parse2.py` 的记录头里有各 `uid` 的 `data_off`/`size`） |
| C dm-verity | `artifacts/verity/` 下 8 个切片：`sys_dmend.bin`、`sys_tail2m.bin`、`p44_tail1m.bin`、`vf/{top,l1_0,l0_0,l0_1,d5}.bin` | 从 system 分区 dump 里按块切；`verify_verity.py` 第 12–19 行就是要的文件名 |
| D 证书身份 | `artifacts/ta/certs/cert_{851_0,7d3_0,sl}.der` | 从 TA 的 unit `0x851` / `0x7D3` 剥离 DER |
| E verity_key 穷举 | `artifacts/verity/vf/verity_key.raw`、`meta8.bin` | 从 system 分区的 `/verity_key` 与元数据区取 |
| F/G/H 在线 | 设备 + `adb forward` | 见 [device-access.md](device-access.md) |

缺文件时脚本会直接报 `FileNotFoundError`——这是预期行为，不是脚本坏了。

---

## A. 离线：TA 记录结构 ★

```bash
python3 analysis/ta/ta_parse2.py
```

**期望**：配置区 1962 条是稳定的；日志区条数随开机次数变化，所以总数在不同快照上
会在 2080 附近浮动——**不要拿总数当判据**，判据是下面这个结构（本次快照的观察值）：

```
size=2097152  records=2082
  配置区 off<0x40000 : 1962 条，分 2 个存储块：
      - 1581 条(uid 0000..6d5e,单调=True)
      - 381 条(uid 6c13..11fd4,单调=True)
  日志区 off>=0x60000:  120 条  uid 单调=False  (乱序属正常：追加写)
  重复 uid           :   12 个
  填充规则(flags低字节): 1200 符合 / 11 例外 / 871 无需填充
```

前三条短记录必须精确匹配：`0x47`→13B `"SW_DEFAULT"`、`0x52`→4B `"0000"`、`0x55`→6B `"000000"`。
这三条是**外部权威尺寸**（来自 `tad`），是记录格式唯一的硬验证。

## B. 离线：bootconfig 解码 ★

```bash
# bootcfg_84f.bin 不入库（解码产物），先从 TA 取出 unit 0x84F 的 97 字节
python3 analysis/ta/bootcfg_decode.py artifacts/ta/bootcfg_84f.bin
```

**期望**：魔数 `1A CE`，6 条顶层 TLV **恰好耗完 97 字节（零残留）**；
type1 = 启动触发器表（USB-OTG / GPIO×4 / PowerKey），type2 = unit 引用表（`0x9A9`、`0x8B3`）。
**关键：不含任何 rooting 字段。**

## C. 离线：dm-verity 全链 ★

```bash
python3 analysis/verity/verify_verity.py
```

**期望**：A–E 共 **六次比较**（D 节比两次）全部 `MATCH`、零 `MISMATCH`，且退出码为 0。账目也要闭合：

```
表: ver=1 dbs=4096 hbs=4096 num_data_blocks=1335440 hash_start_block=1335448 alg=sha256
L0 条目 1335440 -> L0 块 10434 -> L1 块 82 -> 顶层 1
数据+元数据+树 = 1345965 块, 分区 1346048 块 -> 尾部填充 83 块 = 339968 B
[A] sha256(salt||4096 零块) == 尾部重复值        MATCH
[B] sha256(salt||顶层块)   == 表里 root          MATCH
[C] 顶层条目0              == sha256(salt||L1块0) MATCH
[D] L1块0 条目0            == sha256(salt||L0块0) MATCH
    L1块0 条目1            == sha256(salt||L0块1) MATCH
[E] L0块0 条目5            == sha256(salt||数据块5) MATCH
```

末尾还有一行 `[汇总] 6 次比较：全部 MATCH`。**任一处不匹配时脚本返回 1**，
所以按退出码判比数 `MATCH` 个数可靠——数 `MATCH` 会把「5 个对、1 个错」看成通过。

这一组结果同时证明了三件事：verity **已启用**、哈希树**root-first**、
尾部 705KB 的重复值**不是 root** 而是带盐零块哈希。

## D. 离线：证书身份 ★

```bash
openssl x509 -inform der -in artifacts/ta/certs/cert_851_0.der -noout -subject -issuer -dates
openssl x509 -inform der -in artifacts/ta/certs/cert_7d3_0.der -noout -subject
openssl x509 -inform der -in artifacts/ta/certs/cert_sl.der  -noout -subject
```

**期望**：`0x851` → `CN=S1_SL`（签发者 `CN=S1_Root_f936`，RSA-2048 / sha256WithRSA，2014–2034）；
`0x7D3` → `CN=S1_HWConf`。`SL` = **SimLock**，不是 "security level"。

## E. 离线：`0x851` 签名自证 ★

```bash
python3 analysis/verity/verify_sig.py      # 注意：这是 /verity_key 的穷举，见下
```

⚠️ 两个不同的事，别混：
- `verify_sig.py` 穷举 `/verity_key`（524B 二进制）所有 256B 窗口作模数，
  **期望结果是"找到 PKCS#1 v1.5 结构的组合: 0"** —— 即公钥来源仍未定（已知未解）。
- `0x851` 的验签是**另一套**：结构 `[20B 头][691B 证书][3B 02 01 00][256B 签名]` = 970，
  用证书公钥 `sig^65537 mod n` 解出合法 DigestInfo，并解出合法 DigestInfo（32 字节摘要值不记录）。
  这一步当时是手工 openssl/脚本做的，**尚未脚本化**（`artifacts/ta/certs/mod_sl.txt` 存了模数可用于重建）。

## F. 在线：TA 全量比对（只读，约 1 分钟）

```bash
adb forward tcp:19999 localfilesystem:/dev/socket/tad
cd analysis/ta && python3 ta_verify_live.py
adb forward --remove tcp:19999
```

**期望**：2070 个 uid 中 1962 个可读，**尺寸 100% 一致、内容 0 差异**。
这一项把记录格式从【强推断】升为【实测】。

```bash
cd analysis/ta && python3 ta_uid_scan.py     # 扫描"设备有、dump 无"的可读 unit
```

**期望**：0 条。若不为 0，说明解析器漏记录了。

## G. 在线：TAD 可见性（只读）

```bash
adb forward tcp:19999 localfilesystem:/dev/socket/tad
python3 -c "
from analysis.ta.tadif import Tad
t=Tad(); t.open(1)
for u in (0x47,0x7DA,0x84F,0x851,0x8B2):
    print(hex(u), t.getsize(u))
"
```

**期望**：`0x47` → 13；其余 → `Unit not found(4)`。
这证明了**服务端过滤**，不能推出"unit 不存在"。

## H. 在线：fastboot 判定

```bash
adb reboot bootloader
fastboot getvar all                            # 7 个变量，无 is-unlocked
fastboot oem unlock 0x0000000000000000         # Command not allowed
fastboot reboot
```

零写入、零风险。判据见 [`device-access.md`](device-access.md) §4。

---

## 不做的事（红线）

| 动作 | 原因 |
|---|---|
| 写 TA 任何配置 unit | 无现场恢复入口（ADR 0005） |
| 写 `0x7DA` / `0x1046C` | 签名真实，改了必被拒（ADR 0008） |
| `tad` 的 `op=4`（write） | 从未测过，属于写入 |
| `fastboot flash` | BL 锁，必然被拒；反复试没有信息增益 |
| 在 Permissive 状态下"验证"安全行为 | 状态本身是 root 的副作用，不代表设备默认 |
