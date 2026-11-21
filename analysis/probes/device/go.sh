#!/system/bin/sh
# 用法: go.sh <探针名> <日志后缀>
P="$1"
TAG="$2"
: > /data/local/tmp/p78.log
nohup /data/local/tmp/ks.sh /data/local/tmp/kk$TAG.txt >/dev/null 2>&1 &
sleep 2
cd /data/local/tmp
nohup ./$P >/dev/null 2>&1 &
sleep 45
