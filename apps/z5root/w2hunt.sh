#!/bin/zsh
# 反复跑 shell 版 exploit, 直到 dmesg 出现 oops (panic_on_oops 已置 0, 不会重启)
# 目的: 抓到 W2 写 cap_bset 时崩溃的内核调用栈
set -u
cd "$(dirname "$0")" || exit 1
OUT=../../artifacts/reports/forensics
mkdir -p "$OUT"

adb shell 'rm -f /data/local/tmp/dmesg_mark' >/dev/null 2>&1
adb shell 'dmesg | wc -l' > "$OUT/w2_base.txt" 2>/dev/null
BASE=$(tr -dc '0-9' < "$OUT/w2_base.txt")
echo "dmesg baseline lines = $BASE"

for i in $(seq 1 25); do
  # 1) 清掉上一轮挂住的 p149 (panic_on_oops=0, 杀进程不会重启)
  adb shell 'for p in $(ps | grep "[p]149" | tr -s " " | cut -d" " -f2); do kill -9 $p 2>/dev/null; done' >/dev/null 2>&1
  sleep 1

  # 2) 跑一次
  adb shell "setsid /data/local/tmp/p149 > /data/local/tmp/w2_$i.log 2>&1 &" >/dev/null 2>&1
  sleep 18

  # 3) 取这次日志的末行
  LOG=$(adb shell "tail -c 400 /data/local/tmp/w2_$i.log 2>/dev/null" 2>/dev/null | tr -d '\r' | tr '\n' '|')
  echo "[$i] log: $LOG"

  # 4) 看 dmesg 有没有 oops
  adb shell dmesg > "$OUT/w2_dmesg_$i.txt" 2>/dev/null
  N=$(python3 - "$OUT/w2_base.txt" "$OUT/w2_dmesg_$i.txt" <<'PY'
import sys
a=open(sys.argv[1],errors='replace').read().splitlines()
b=open(sys.argv[2],errors='replace').read().splitlines()
sa=set(a)
new=[l for l in b if l not in sa]
bad=[l for l in new if ('Unable to handle' in l or 'Internal error' in l or 'Oops' in l
      or 'Kernel panic' in l or 'Call trace' in l or 'slab' in l.lower() and 'corrupt' in l.lower())]
print(len(bad))
for l in bad[:40]:
    print(l, file=sys.stderr)
PY
)
  echo "    oops-ish new lines: $N"
  if [ "$N" != "0" ]; then
    echo "=== GOT IT at iter $i ==="
    adb shell dmesg > "$OUT/w2_OOPS.txt" 2>/dev/null
    break
  fi
done
echo "done"
