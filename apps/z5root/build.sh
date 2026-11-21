#!/bin/bash
# 完全离线打 APK: javac(JDK17) -> D8(r8.jar, 来自 cmdline-tools) -> 手写 AXML -> jarsigner
set -e
cd "$(dirname "$0")"

TOOLS=../../tools
export JAVA_HOME="$PWD/$TOOLS/jdk17/Contents/Home"
JAVA="$JAVA_HOME/bin/java"
JAVAC="$JAVA_HOME/bin/javac"
JARSIGNER="$JAVA_HOME/bin/jarsigner"
KEYTOOL="$JAVA_HOME/bin/keytool"
R8="$PWD/$TOOLS/sdk/cmdline-tools/latest/lib/r8.jar"

OUT=build
python3 -c "import shutil,os; shutil.rmtree('build', True)"
mkdir -p "$OUT/classes" "$OUT/dex"

echo "== 1) javac (--release 8)"
"$JAVAC" --release 8 -nowarn -d "$OUT/classes" \
    $(find stubs src -name '*.java') 2>&1 | grep -v "^Note:" || true
ls "$OUT/classes/com/z5/root/"

echo "== 2) D8 -> classes.dex"
"$JAVA" -cp "$R8" com.android.tools.r8.D8 \
    --release --min-api 21 --no-desugaring \
    --lib "$OUT/classes" \
    --output "$OUT/dex" \
    "$OUT/classes/com/z5/root/"*.class
ls -la "$OUT/dex"

echo "== 3) AndroidManifest.xml (AXML)"
python3 tools/axml.py "$OUT/AndroidManifest.xml" "${1:-full}"

echo "== 4) 组包"
python3 - "$OUT" <<'PY'
import sys, os, zipfile
out = sys.argv[1]
apk = os.path.join(out, "unsigned.apk")
with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as z:
    z.write(os.path.join(out, "AndroidManifest.xml"), "AndroidManifest.xml")
    z.write(os.path.join(out, "dex", "classes.dex"), "classes.dex")
    for a in ("assets/z5root", "assets/su"):
        if os.path.exists(a):
            z.write(a, a.split("/")[-1] and a)
print("apk:", apk, os.path.getsize(apk), "bytes")
PY

echo "== 5) 签名 (v1, JAR signing)"
if [ ! -f z5.keystore ]; then
  "$KEYTOOL" -genkeypair -keystore z5.keystore -storetype JKS \
    -storepass android -keypass android -alias z5 -keyalg RSA -keysize 2048 \
    -validity 10000 -dname "CN=z5, OU=z5, O=z5, C=CN" 2>&1 | tail -2
fi
cp "$OUT/unsigned.apk" "$OUT/signed.apk"
"$JARSIGNER" -keystore z5.keystore -storepass android -keypass android \
    -sigalg SHA256withRSA -digestalg SHA-256 \
    "$OUT/signed.apk" z5 2>&1 | tail -3

echo "== done"
ls -la "$OUT/signed.apk"
