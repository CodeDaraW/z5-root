#!/bin/zsh
# 完整冷启动验收: 重启 -> 不触发检查 -> 点 App -> 轮询等 root -> 汇总
# 用法: ./accept.sh [轮数]
# 每轮输出: 冷启动基线 / 拿到 root 用时 / 期间是否重启(uptime 是否归零) / 重试次数
set -u
cd "$(dirname "$0")" || exit 1
N=${1:-1}
OUT=../../artifacts/reports/accept
mkdir -p "$OUT"
PREV=/storage/emulated/0/Android/data/com.z5.root/files/prev

# 只在开始时干净装一次 (每轮都 install -r 会堆出 com.z5.root-N 重复目录,
# 会让包变成 stopped/notLaunched, 收不到 BOOT_COMPLETED)
adb uninstall com.z5.root >/dev/null 2>&1
adb install -r build/signed.apk >/dev/null 2>&1

for r in $(seq 1 "$N"); do
  echo "================ 第 $r / $N 轮 ================"
  adb reboot >/dev/null 2>&1
  sleep 25
  for i in $(seq 1 40); do
    if adb shell pm list packages 2>/dev/null | grep -q com.z5; then break; fi
    sleep 3
  done

  # 冷启动基线(未触发)
  echo "[冷启动 未触发]"
  adb shell 'echo -n "  enforce="; getenforce; echo -n "  panic_on_oops="; cat /proc/sys/kernel/panic_on_oops; echo -n "  uptime="; cut -d" " -f1 /proc/uptime; echo -n "  /mnt/su: "; ls -l /mnt/su 2>&1 | head -1' 2>&1 | tr -d '\r'

  adb logcat -c >/dev/null 2>&1
  T0=$(date +%s)
  # ★ 必须走 LAUNCHER 路径 (= 真人点图标)。
  #   `am start -n` 不会清除包上的 stopped/notLaunched 标志,
  #   而这两个标志为 true 时系统不会给该包投递 BOOT_COMPLETED,
  #   自动续跑就永远不会触发。
  adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1
  adb shell monkey -p com.z5.root -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
  echo "[已点击 App, 开始轮询]"
  OK=0
  for t in $(seq 1 90); do
    sleep 3
    S=$(adb shell 'echo -n "$(getenforce) "; /mnt/su -c "id -u" 2>/dev/null; echo -n " up=$(cut -d" " -f1 /proc/uptime)"' 2>/dev/null | tr -d '\r')
    case "$S" in
      Permissive*0*) OK=1; echo "  t=$((t*3))s  -> $S"; break ;;
    esac
    if [ $((t % 5)) -eq 0 ]; then echo "  t=$((t*3))s  -> $S"; fi
  done
  T1=$(date +%s)

  if [ "$OK" = "1" ]; then
    echo "  ★ 第 $r 轮: 成功 (用时 $((T1-T0))s)"
  else
    echo "  × 第 $r 轮: 180s 内未拿到 root"
  fi

  echo "[最终状态]"
  adb shell 'echo -n "  enforce="; getenforce; echo -n "  panic_on_oops="; cat /proc/sys/kernel/panic_on_oops; echo -n "  uptime="; cut -d" " -f1 /proc/uptime; echo -n "  su -c id -u = "; /mnt/su -c "id -u" 2>&1; echo -n "  caps: "; /mnt/su -c "grep CapEff /proc/self/status" 2>&1' 2>&1 | tr -d '\r'

  echo "[app 侧埋点]"
  adb shell "cat $PREV/att.txt 2>/dev/null" 2>&1 | tr -d '\r' | sed 's/^/  att: /'
  adb pull "$PREV/rep.bin" "$OUT/rep_r$r.bin" >/dev/null 2>&1
  python3 - "$OUT/rep_r$r.bin" <<'PY'
import sys, re, os
if not os.path.exists(sys.argv[1]):
    print("  (没有 rep.bin)"); raise SystemExit
d=open(sys.argv[1],'rb').read()
e=len(d)
while e>0 and d[e-1]==0: e-=1
t=[x for x in re.findall(r'[ -~\n]+', d[:e].decode('latin-1')) if x.strip()]
print("  rep: " + " | ".join(t)[-500:])
PY
  echo "  logcat(Z5):"
  adb logcat -d 2>/dev/null | grep -E "Z5" | tail -8 | sed 's/^/    /'
  echo "---------------- 第 $r 轮结束 ----------------"
done
