#!/bin/zsh
# 长稳观察: root 在位, 每 3 分钟抽查一次关键子系统
# 用法: ./soak.sh [分钟]
set -u
cd "$(dirname "$0")" || exit 1
MIN=${1:-60}
OUT=../../artifacts/reports/soak_$(date +%m%d_%H%M).log
: > "$OUT"

chk() {
  echo "===== $(date +%H:%M:%S) =====" | tee -a "$OUT"
  adb shell '
    echo -n "uptime="; cut -d" " -f1 /proc/uptime
    echo -n "enforce="; getenforce
    echo -n "su="; /mnt/su -c "id -u" 2>&1
    echo -n "caps="; /mnt/su -c "grep CapEff /proc/self/status" 2>&1 | cut -f2
    echo -n "procs="; ps | grep -cE "system_server|cameraserver|mediaserver|netd|zygote|vold|rild"
    echo -n "sysui_pid="; ps | grep [s]ystemui | tr -s " " | cut -d" " -f2
    echo -n "z5alive="; ps | grep "[z]5root" | grep -vc " Z "
    echo -n "z5zombie="; ps | grep "[z]5root" | grep -c " Z "
    echo -n "memfree="; grep MemFree /proc/meminfo | tr -s " " | cut -d" " -f2
    echo -n "wifi="; dumpsys wifi | grep -m1 "Wi-Fi is"
    echo -n "ssid="; dumpsys wifi | grep -m1 -o "SSID: [^,]*"
    echo -n "cam="; dumpsys media.camera | grep -m1 "Number of camera devices"
    echo -n "bt="; getprop bluetooth.enable_timeout_ms >/dev/null 2>&1; getprop | grep -m1 "bluetooth.state"
    echo -n "batt="; dumpsys battery | grep -m1 -E "level" 
    echo -n "audio="; dumpsys audio | grep -m1 -E "mMode|Audio Devices"
    echo -n "oops="; dmesg | grep -ciE "Unable to handle|Internal error|Kernel panic"
    echo -n "avcdeny="; dmesg | grep -c "avc: denied"
  ' 2>&1 | tr -d '\r' | sed 's/^/  /' | tee -a "$OUT"
}

END=$(( $(date +%s) + MIN*60 ))
while [ "$(date +%s)" -lt "$END" ]; do
  chk
  sleep 180
done
echo "soak done -> $OUT"
