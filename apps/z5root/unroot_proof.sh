#!/bin/zsh
# 从【app 域】证明 root 到底在不在。
#
# 为什么不能只看 adb shell:
#   /mnt/su 的 SELinux label 是 u:object_r:shell_data_file:s0,
#   从 shell 域 exec 它是允许的 -> `adb shell /mnt/su -c id -u` 重启后依然会打 0,
#   这会被误读成"root 还在"。真正有意义的是**普通 app 域**能不能 exec 它。
#
# 做法: 拉起 com.z5.sutest (一个只调 exec("/mnt/su",...) 的普通 app),
#       它会把完整报告打到 logcat 的 SUTEST 标签里 (不需要 root 就能读)。
#
# 用法: ./unroot_proof.sh
set -u
cd "$(dirname "$0")" || exit 1

echo "=== app 域 root 检查 $(date +%H:%M:%S) ==="
adb install -r ../sutest/build/signed.apk >/dev/null 2>&1
adb logcat -c >/dev/null 2>&1
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1
adb shell monkey -p com.z5.sutest -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 12

# logcat 行形如 "11-11 05:34:05.123  1234  1240 I SUTEST  : <msg>", 先剥前缀
REPORT=$(adb logcat -d -s SUTEST 2>&1 | grep " SUTEST " | sed 's/^.* SUTEST *: //' | tr -d '\r')

echo "--- 报告 (logcat SUTEST) ---"
echo "$REPORT"

echo ""
echo "--- 判读 ---"
if echo "$REPORT" | grep -q "uid=0(root)"; then
  echo "★ app 域拿到 uid=0(root) -> root 在位"
elif echo "$REPORT" | grep -qiE "Permission denied|EXEC FAIL|TIMEOUT"; then
  echo "√ app 域 exec /mnt/su 被拒 -> root 不在 (重启后应有的状态)"
else
  echo "? 报告不完整, 请人工看上面的内容"
fi
