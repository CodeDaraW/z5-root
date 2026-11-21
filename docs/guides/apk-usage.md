# Z5 一键 ROOT 使用说明

适用于 **Sony SO-01H（Z5 / sumire，Android 6.0.1，32.1.F.1.98）**。
APK：`apps/z5root/build/signed.apk`（24 KB 左右）。

---

## 1. 安装

```
adb install -r apps/z5root/build/signed.apk
```

或者把 `signed.apk` 拷进手机，用文件管理器点开安装（需要允许"未知来源"）。

装完桌面上会出现 **Z5 Root**。

---

## 2. 用一次

1. 点桌面上的 **Z5 Root**。
2. 点 **开始 ROOT**。
3. 停在当前页面等。**先有 15 秒倒计时**，然后才开始动手；
   总共一般 **20~80 秒**，屏幕上有进度和 exploit 的实时输出。
4. 出现 `★ 成功: su 已就位` 就成了。

> 那 15 秒不是卡住，也不能省：系统要先把"你启动过本应用"写进磁盘。
> 万一后面崩溃重启，开机后才认得出该继续干活。

成功后 su 在 **`/mnt/su`**（`/data/local/su` 也有一份），
权限 `-rwsr-sr-x root root`。

验证：

```
adb shell /mnt/su -c id
# uid=0(root) gid=0(root) groups=0(root),3003(inet),9997(everybody),...
```

---

## 3. 失败了会怎样

失败有两种，都**不需要你做什么**：

| 情况 | 现象 | 自动处理 |
|---|---|---|
| UAF 竞态没赢（最常见） | 页面显示第 1/2/3 次尝试，最后 `× 三次都没成功` | 同一开机内**自动重试 3 次**，手机不重启 |
| `MCAST_LEAVE_GROUP` 那一下触发内核 panic | **黑屏重启一次**（约 40% 概率，只在"建立 UAF"阶段） | 开机后 **App 自动继续跑**，最多再试 3 次，成功后不再跑 |

也就是说：**正常情况下你只需要点一次**。剩下的它自己扛。

三次都没成功的话，再点一次图标重来即可。

> **极少数情况**：如果重启后屏幕恢复正常、但 `/mnt/su` 不存在、
> 也没有"正在 root"的界面，说明这次开机没能自动续上
> （安装后第一次点击就崩、且系统还没来得及记住"你启动过"，会这样）。
> **再点一次图标就行**，第二次一定能接上。

---

## 4. 不想 root 的时候

**什么都不用做，它也不会跑。**

- 没点过 → 开机后 `BootReceiver` 检查到没有 `pending.txt`，直接返回，一行代码都不执行。
- 点过并且成功了 → `pending.txt` 被删掉，之后开机同样不动。
- 只有"点过但还没成功"这一种状态，才会在开机时自动续跑，且上限 3 次。

---

## 5. 给别的 App 用

任意第三方 App，用最普通的 `Runtime.exec` 就能拿到 uid=0 + 满 caps：

```java
Process p = Runtime.getRuntime().exec(new String[]{"/mnt/su", "-c", "id"});
```

实测（`apk2`，包名 `com.z5.sutest`，完全不参与 exploit）：

```
id -u                     → 0
CapPrm / CapEff           → 00000000ffffffff / 00000000ffffffff
CapBnd                    → 00000006ffffffff
ls /data/data | wc -l     → 415          （能列全部 app 私有目录）
head -1 /data/misc/wifi/wpa_supplicant.conf → ctrl_interface=/data/misc/wifi/sockets
```

注意：`/mnt/su` 是**免授权**的（不做弹窗确认），任何 App 都能直接用。
这是"给其他 app 用"的代价 —— 要换成"每次弹窗确认"需要另写一个 su 管理器。

---

## 6. 撤销 / 恢复原厂

**重启手机 = root 消失，而且是干净的消失。**

实测（06:28 重启后立刻体检）：

```
getenforce      : Enforcing          ← 回到强制模式
panic_on_oops   : 1                  ← 回到原厂默认
/mnt/su         : No such file or directory   ← /mnt 是 tmpfs, 重启即清空
z5root 进程     : 无
/ data/local/su : -rwsr-sr-x root root  (文件还在)
  执行它        : "su: 没有 root。请先把 Z5 Root 应用跑一次。"
```

也就是说 `/data/local/su` 这个文件虽然留在 /data 里（不会自己消失），
但它**只是守护进程的客户端** —— 守护进程一没，它就明确拒绝，不会给出 root。
不用管它，也不用删。

要彻底清干净：`adb uninstall com.z5.root`，再重启一次。
`/data/local/su` 想删的话（用 root 时）：
`adb shell /mnt/su -c "mv /data/local/su /data/local/tmp/"`。

---

## 7. 已知取舍（**重要，请读**）

1. **root 在位期间 SELinux 是 `Permissive`**（全局）。
   这是提权的必要前提（要往 `cred` 里写、要 exec 带 suid 的二进制）。
   重启后自动恢复 `Enforcing`。

2. **成功后 `panic_on_oops` 保持 0，直到下次重启**。
   故意不恢复：exploit 建出来的 UAF 现场会一直挂着，万一日后内核碰一下，
   恢复成 1 就会立刻重启手机 —— 那是最坏的结果。留在 0 的话最多杀掉一个进程。
   重启即回到原厂默认值 1。

3. **不要手动 `kill` 名为 `z5root` 的进程**。
   它持着那个 UAF socket，进程一退出 `ip_mc_drop_socket` 就可能 panic 重启。
   想撤掉 root 就重启手机。

4. **不要把本 App 留在"最近任务"里**（这是历史坑）。
   App 自己在跑完后 6 秒会把自己从最近任务移除，正常用不会遇到。
   root 在位时手动进多任务界面有概率让 SystemUI 卡顿/重启 —— 这是内存紧张 +
   LMK 与 UAF 现场交互导致的老问题，App 已经做了规避（`oom_score_adj=-1000`），
   但极端情况下仍可能发生。**没有 root 时进多任务完全正常。**

5. 只在这台机器、这个固件版本上验证过。别的机型/版本不要套用。

---

## 8. 出问题看哪里

App 会把现场文件复制到：

```
/sdcard/Android/data/com.z5.root/files/prev/
  step.txt out.txt rep.bin att.txt pending.txt meta.txt
```

`att.txt` 记录每次尝试的开始/结束，`out.txt` 是 exploit 的 stdout，
`rep.bin` 是 exploit 自己写的进度标记（崩溃点就靠它定位）。

日志：

```
adb logcat -s Z5
```
