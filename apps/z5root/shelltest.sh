#!/bin/zsh
# 冷启动 -> 跑 shell 版 exploit -> 看 rep.bin 精确进度
# 用法: ./shelltest.sh <adb上的exploit名> [等待秒数]
set -u
cd "$(dirname "$0")" || exit 1
EXE=${1:-p150}
WAIT=${2:-30}
OUT=../../artifacts/reports/forensics/shell
mkdir -p "$OUT"

echo "== reboot =="
adb reboot >/dev/null 2>&1
sleep 25
for i in $(seq 1 40); do
  if adb shell pm list packages 2>/dev/null | grep -q com.z5; then echo "pm ready (try $i)"; break; fi
  sleep 3
done

echo "== cold state =="
adb shell 'echo -n "enforce="; getenforce; echo -n " panic_on_oops="; cat /proc/sys/kernel/panic_on_oops; echo -n " uptime="; cut -d" " -f1 /proc/uptime' 2>&1 | tr -d '\r'

echo "== run $EXE =="
adb shell ": > /data/local/tmp/rep.bin; setsid /data/local/tmp/$EXE > /data/local/tmp/shell_$EXE.log 2>&1 &" >/dev/null 2>&1
sleep "$WAIT"

echo "== after =="
adb shell 'echo -n "enforce="; getenforce; echo -n " panic_on_oops="; cat /proc/sys/kernel/panic_on_oops; echo -n " uptime="; cut -d" " -f1 /proc/uptime; ls -l /mnt/su 2>&1; echo -n "su -u="; /mnt/su -c "id -u" 2>&1' 2>&1 | tr -d '\r'

echo "== rep.bin 进度 =="
adb pull /data/local/tmp/rep.bin "$OUT/rep_$EXE.bin" >/dev/null 2>&1
python3 - "$OUT/rep_$EXE.bin" <<'PY'
import sys, re
d=open(sys.argv[1],'rb').read()
end=len(d)
while end>0 and d[end-1]==0: end-=1
txt=d[:end].decode('latin-1')
toks=[t for t in re.findall(r'[ -~\n]+', txt) if t.strip()]
print(" | ".join(toks)[-1000:])
PY

echo "== stdout 尾部 =="
adb shell "tail -c 300 /data/local/tmp/shell_$EXE.log 2>/dev/null" 2>&1 | tr -d '\r'
echo
