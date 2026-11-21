#!/system/bin/sh
# 内核日志追加采集: 每 0.2s 把 dmesg 末尾 80 行追加到 $1
OUT="$1"
i=0
while true; do
  dmesg 2>/dev/null | tail -80 >> "$OUT"
  echo "--C$i" >> "$OUT"
  i=$((i+1))
  sleep 0.2
done
