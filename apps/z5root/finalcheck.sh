#!/bin/zsh
# 最终交付验收 —— 一条命令跑完用户那句验收标准:
#   "开机我可以手动触发一下 Root，但无论我触发还是不触发，系统功能都应该是正常的。"
#
# 流程:
#   0. 干净安装最终 APK (uninstall + install, 避免 /data/app 堆重复目录)
#   1. 重启, 等系统起来
#   2. 【不触发】阶段取证: enforce / panic_on_oops / 残留 z5root / app 域能不能拿 root
#   3. 点一次图标 (LAUNCHER 路径 = 真人点击), 轮询等 root
#   4. 【触发后】全项: su / caps / SystemUI pid / 僵尸数 / 三方 app 能不能用
#
# 用法: ./finalcheck.sh            （不重启直接测）
#       ./finalcheck.sh reboot     （先重启再测, 完整冷启动）
set -u
cd "$(dirname "$0")" || exit 1
OUT=../../artifacts/reports/accept
mkdir -p "$OUT"

echo "################ 0) 干净安装 ################"
adb uninstall com.z5.root >/dev/null 2>&1
adb install -r build/signed.apk 2>&1 | tail -1
adb shell pm path com.z5.root

if [ "${1:-}" = "reboot" ]; then
  echo "################ 1) 重启 ################"
  adb reboot >/dev/null 2>&1
  sleep 30
  for i in $(seq 1 40); do
    adb shell pm list packages 2>/dev/null | grep -q com.z5.root && break
    sleep 3
  done
  sleep 5
fi

echo "################ 2) 不触发 阶段取证 ################"
adb shell '
  echo -n "  uptime      = "; cut -d" " -f1 /proc/uptime
  echo -n "  getenforce  = "; getenforce
  echo -n "  panic_on_oops = "; cat /proc/sys/kernel/panic_on_oops
  echo -n "  sysui_pid   = "; ps | grep [s]ystemui | tr -s " " | cut -d" " -f2
  echo -n "  z5root 进程 = "; ps | grep -c "[z]5root"
  echo -n "  /mnt/su     = "; ls -l /mnt/su 2>&1 | tr -s " " | cut -d" " -f1,3,4
  echo -n "  pending.txt = "; ls /data/data/com.z5.root/files/pending.txt 2>&1
' 2>&1 | tr -d '\r'

echo "  --- app 域视角 (普通 app 能不能拿到 root) ---"
ADB_SUTEST=$(adb logcat -d -s SUTEST 2>&1 | grep " SUTEST " | sed 's/^.* SUTEST *: //' | tr -d '\r')
if echo "$ADB_SUTEST" | grep -q "uid=0(root)"; then
  echo "    (注: 上面若显示 uid=0, 是重启前那次运行的残留日志)"
fi

echo "################ 3) 点一次, 等 root ################"
adb logcat -c >/dev/null 2>&1
T0=$(date +%s)
# 必须走 LAUNCHER: am start -n 不清 stopped/notLaunched, 会导致收不到 BOOT_COMPLETED
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1
adb shell monkey -p com.z5.root -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
OK=0
for t in $(seq 1 100); do
  sleep 3
  S=$(adb shell 'echo -n "$(getenforce) "; /mnt/su -c "id -u" 2>/dev/null; echo -n " up=$(cut -d" " -f1 /proc/uptime)"' 2>/dev/null | tr -d '\r')
  case "$S" in
    Permissive*0*) OK=1; echo "  t=$((t*3))s  -> $S"; break ;;
  esac
  [ $((t % 5)) -eq 0 ] && echo "  t=$((t*3))s  -> $S"
done
T1=$(date +%s)
[ "$OK" = "1" ] && echo "  ★ 成功, 用时 $((T1-T0))s" || echo "  × 300s 内未拿到 root"

echo "################ 4) 触发后 全项 ################"
adb shell '
  echo -n "  enforce     = "; getenforce
  echo -n "  panic_on_oops = "; cat /proc/sys/kernel/panic_on_oops
  echo -n "  uptime      = "; cut -d" " -f1 /proc/uptime
  echo -n "  sysui_pid   = "; ps | grep [s]ystemui | tr -s " " | cut -d" " -f2
  echo -n "  z5root 总数 = "; ps | grep -c "[z]5root"
  echo -n "  z5root 僵尸 = "; ps | grep "[z]5root" | grep -c " Z "
  echo -n "  su -c id -u = "; /mnt/su -c "id -u" 2>&1
  echo -n "  caps        = "; /mnt/su -c "grep CapEff /proc/self/status" 2>&1
  echo -n "  相机        = "; dumpsys media.camera | grep -m1 "Number of camera devices" | tr -s " " | cut -d" " -f5
  echo -n "  wifi        = "; dumpsys wifi | grep -m1 -o "SSID: [^,]*"
  echo -n "  oops        = "; dmesg | grep -ciE "Unable to handle|Internal error|Kernel panic"
' 2>&1 | tr -d '\r'

echo "  --- 第三方 app (com.z5.sutest) 复验 ---"
./unroot_proof.sh 2>&1 | sed -n '/判读/,$p' | sed 's/^/    /'

echo "  --- app 侧埋点 ---"
adb shell "cat /storage/emulated/0/Android/data/com.z5.root/files/prev/att.txt 2>/dev/null" 2>&1 | tr -d '\r' | sed 's/^/    att: /'
echo "################ 结束 ################"
