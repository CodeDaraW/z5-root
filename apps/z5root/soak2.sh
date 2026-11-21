#!/bin/zsh
# 长稳观察 B: "不触发 root" 的干净态
#
# ★ 重要: 本脚本里 `su_shell=` 这一项**不能**当"有没有 root"的证据。
#   /mnt/su 的 label 是 shell_data_file, 从 adb shell 域 exec 它是允许的,
#   所以重启后这一项照样会打出 0。真正的判据得看 app 域 —> 用 unroot_proof.sh。
#
# 用法: ./soak2.sh [分钟]
set -u
cd "$(dirname "$0")" || exit 1
MIN=${1:-60}
OUT=../../artifacts/reports/soak_clean_$(date +%m%d_%H%M).log
: > "$OUT"

chk() {
  echo "===== $(date +%H:%M:%S) =====" | tee -a "$OUT"
  adb shell '
    echo -n "uptime="; cut -d" " -f1 /proc/uptime
    echo -n "enforce="; getenforce
    echo -n "panic_on_oops="; cat /proc/sys/kernel/panic_on_oops
    echo -n "sysui_pid="; ps | grep [s]ystemui | tr -s " " | cut -d" " -f2
    echo -n "z5proc="; ps | grep -c "[z]5root"
    echo -n "procs="; ps | grep -cE "system_server|cameraserver|mediaserver|netd|zygote|vold|rild"
    echo -n "memfree="; grep MemFree /proc/meminfo | tr -s " " | cut -d" " -f2
    echo -n "pkgs="; pm list packages 2>/dev/null | wc -l
    echo -n "wifi="; dumpsys wifi | grep -m1 "Wi-Fi is"
    echo -n "ssid="; dumpsys wifi | grep -m1 -o "SSID: [^,]*"
    echo -n "cam="; dumpsys media.camera | grep -m1 "Number of camera devices"
    echo -n "batt="; dumpsys battery | grep -m1 -E " level"
    echo -n "oops="; dmesg | grep -ciE "Unable to handle|Internal error|Kernel panic"
    echo -n "avcdeny="; dmesg | grep -c "avc: denied"
  ' 2>&1 | tr -d '\r' | sed 's/^/  /' | tee -a "$OUT"
}

END=$(( $(date +%s) + MIN*60 ))
while [ "$(date +%s)" -lt "$END" ]; do
  chk
  sleep 180
done
echo "soak2 done -> $OUT"
