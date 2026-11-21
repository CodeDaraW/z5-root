#!/bin/zsh
# 开机干净态体检: 证明"没触发 root 时系统就是原厂状态"
# 不重启, 只检查。用法: ./bootcheck.sh
set -u
cd "$(dirname "$0")" || exit 1

echo "=== 开机干净态体检 $(date +%H:%M:%S) ==="
adb shell '
  echo "uptime      : $(cut -d" " -f1 /proc/uptime)"
  echo "getenforce  : $(getenforce)"
  echo "panic_on_oops: $(cat /proc/sys/kernel/panic_on_oops 2>&1)"
  echo "selinux     : $(getprop ro.boot.selinux)"
  echo ""
  echo "--- /mnt/su ---"
  ls -l /mnt/su 2>&1
  echo "  exec test : $(/mnt/su -c "id -u" 2>&1 | head -1)"
  echo ""
  echo "--- 残留进程 ---"
  ps | grep "[z]5root" || echo "  (无 z5root 进程, 正确)"
  echo ""
  echo "--- 持久化的 su (只该是客户端, 不该能给 root) ---"
  ls -lZ /data/local/su 2>&1
  echo "  exec test : $(/data/local/su -c "id -u" 2>&1 | head -1)"
  echo ""
  echo "--- App 安装路径 (shell 看不到 /data/app, 只能用 pm) ---"
  pm path com.z5.root 2>&1
  echo ""
  echo "--- 关键服务 ---"
  ps | grep -cE "system_server|cameraserver|mediaserver|netd|zygote|vold|rild"
  echo ""
  echo "--- 内核异常 ---"
  echo "oops : $(dmesg | grep -ciE "Unable to handle|Internal error|Kernel panic")"
  echo "avc  : $(dmesg | grep -c "avc: denied")"
  echo ""
  echo "--- PKMS 解析报错 (应为 0) ---"
  dmesg | grep -c "Failed to parse"
'
echo "=== 体检结束 ==="
