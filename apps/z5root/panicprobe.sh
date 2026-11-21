#!/bin/zsh
# 反复触发直到抓到一次 panic 的完整 dmesg；成功则记录并继续。
# 不删除任何文件：日志用 : > 清空。

cd "$(dirname "$0")" || exit 1
LOG=../../artifacts/reports/panic_capture.log
: > "$LOG"
DM=../../artifacts/reports/panic_dmesg.log
: > "$DM"

echo "=== start $(date) ===" >> "$LOG"

# 宿主机侧持续抓 dmesg；断连自动重连
(
  while true; do
    adb shell dmesg -w >> "$DM" 2>/dev/null
    sleep 1
  done
) &
CAP=$!

for attempt in $(seq 1 6); do
  echo "--- ATTEMPT $attempt  $(date +%H:%M:%S) ---" >> "$LOG"
  adb reboot >/dev/null 2>&1
  sleep 26
  ok=0
  for i in $(seq 1 40); do
    if adb shell pm list packages 2>/dev/null | grep -q com.z5; then ok=1; break; fi
    sleep 3
  done
  if [ "$ok" != "1" ]; then
    echo "  pm not ready, skip" >> "$LOG"
    continue
  fi
  echo "  pm ready" >> "$LOG"
  adb shell am start -n com.z5.root/.MainActivity >/dev/null 2>&1
  sleep 80
  U=$(adb shell cat /proc/uptime 2>/dev/null | tr -d '\r' | cut -d' ' -f1)
  E=$(adb shell getenforce 2>/dev/null | tr -d '\r')
  S=$(adb shell /mnt/su -c "id -u" 2>/dev/null | tr -d '\r')
  echo "  RESULT uptime=$U enforce=$E suid=$S" >> "$LOG"
  if [ "$E" = "Permissive" ] && [ "$S" = "0" ]; then
    echo "  => SUCCESS (root ok)" >> "$LOG"
  else
    echo "  => FAILED (likely panic-reboot)" >> "$LOG"
  fi
done

kill $CAP 2>/dev/null
echo "=== done $(date) ===" >> "$LOG"
