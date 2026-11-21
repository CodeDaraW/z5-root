#!/bin/zsh
# 冷启动后用 adb shell 版 exploit 触发，抓 kmsg（klogw 在 shell 域能落盘）。
cd "$(dirname "$0")" || exit 1
OUT=../../artifacts/reports/shellrun.log
: > "$OUT"

echo "=== reboot $(date +%H:%M:%S) ===" >> "$OUT"
adb reboot >/dev/null 2>&1
sleep 26
for i in $(seq 1 40); do
  if adb shell true 2>/dev/null; then break; fi
  sleep 3
done
sleep 5
echo "uptime: $(adb shell cut -d' ' -f1 /proc/uptime 2>/dev/null | tr -d '\r')" >> "$OUT"
echo "enforce: $(adb shell getenforce 2>/dev/null | tr -d '\r')" >> "$OUT"
K0=$(adb shell 'wc -c /data/local/tmp/klog.txt' 2>/dev/null | tr -d '\r' | tr -s ' ' | cut -d' ' -f1)
echo "klog offset: $K0" >> "$OUT"

# 前台跑（保持 adb 连接存活），失败会退出/被杀，成功会一直 hang
( adb shell 'cd /data/local/tmp && ./p149 > o149.txt 2>&1' >/dev/null 2>&1 ) &
RUN=$!

for i in $(seq 1 24); do
  sleep 5
  U=$(adb shell 'cut -d" " -f1 /proc/uptime' 2>/dev/null | tr -d '\r')
  echo "  t=$((i*5))s uptime=$U" >> "$OUT"
  if [ -z "$U" ]; then
    echo "  adb lost (device likely rebooted)" >> "$OUT"
    break
  fi
done

kill $RUN 2>/dev/null

echo "--- o149.txt ---" >> "$OUT"
adb shell 'cat /data/local/tmp/o149.txt' 2>/dev/null | tr -d '\r' >> "$OUT"
echo "--- enforce/su now ---" >> "$OUT"
adb shell 'getenforce; ls -l /mnt/su; /mnt/su -c "id -u"' 2>/dev/null | tr -d '\r' >> "$OUT"
echo "--- kmsg from offset ---" >> "$OUT"
adb shell "tail -c +$K0 /data/local/tmp/klog.txt" 2>/dev/null | tr -d '\r' | tail -120 >> "$OUT"
echo "=== done $(date +%H:%M:%S) ===" >> "$OUT"
