#!/bin/bash
# 重新生成 APK 内置的两个 aarch64 裸 ELF：
#   assets/z5root  ← analysis/probes/device/probe_app.c   （root 服务端 / exploit 载荷）
#   assets/su      ← analysis/probes/su/su.c              （setuid 客户端）
#
# 为什么不用 NDK：会链进 libc（体积数 MB + 动态链接器路径问题）。
# 这里用 clang 交叉编译成 freestanding .o，再由 mkelf.py 手工拼成最小 ELF64
# （macOS 上没有 ld.lld，无法直接链出 aarch64 ELF）。
#
# 前置：Xcode Command Line Tools 提供的 clang（Apple clang 亦可）+ python3
# 产物与 2026-11-11 提交进 APK 的二进制逐字节一致，可自行核对：
#   z5root  sha256 806d511d5a7f0c631614dac4d11124d71e9615096ba17d62669609f34f63745c
#   su      sha256 f683d784f4a6382abb8fff3ab8668479bb19748badcf18ba4d15745e1c242f64
set -e
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)

CC=${CC:-clang}
# -ffreestanding -nostdlib：不依赖 Android libc；入口由源码里的 _start 提供
CFLAGS="--target=aarch64-linux-gnu -O2 -ffreestanding -fno-builtin -nostdlib -fno-stack-protector"
MKELF="$ROOT/analysis/probes/device/mkelf.py"
OUT=build/assets

mkdir -p "$OUT"

build() {
    local name="$1" src="$2"
    echo "== $name ← ${src#$ROOT/}"
    "$CC" $CFLAGS -c "$src" -o "$OUT/$name.o"
    python3 "$MKELF" "$OUT/$name.o" "$OUT/$name" >/dev/null
    cp "$OUT/$name" "assets/$name"
    ls -l "assets/$name" | awk '{print "   " $5 " bytes"}'
}

build z5root "$ROOT/analysis/probes/device/probe_app.c"
build su     "$ROOT/analysis/probes/su/su.c"

echo "== done：assets/ 已更新，接着跑 build.sh 打包"
