#!/bin/bash
# 第三方验证 App：com.z5.sutest
# 复用 z5root/ 的 JDK、r8、axml、keystore，完全离线。
set -e
cd "$(dirname "$0")"

JAVA_HOME="../../tools/jdk17/Contents/Home"
JAVA="$JAVA_HOME/bin/java"
JAVAC="$JAVA_HOME/bin/javac"
JARSIGNER="$JAVA_HOME/bin/jarsigner"
R8="../../tools/sdk/cmdline-tools/latest/lib/r8.jar"
KEYSTORE="../z5root/z5.keystore"

OUT=build
python3 -c "import shutil; shutil.rmtree('build', True)"
mkdir -p "$OUT/classes" "$OUT/dex"

echo "== 1) javac"
"$JAVAC" --release 8 -nowarn -cp ../z5root/stubs -d "$OUT/classes" \
    $(find src -name '*.java') 2>&1 | grep -v "^Note:" || true
ls "$OUT/classes/com/z5/sutest/"

echo "== 2) D8"
"$JAVA" -cp "$R8" com.android.tools.r8.D8 \
    --release --min-api 21 --no-desugaring \
    --lib "$OUT/classes" --output "$OUT/dex" \
    "$OUT/classes/com/z5/sutest/"*.class
ls -la "$OUT/dex"

echo "== 3) manifest"
python3 -c "
import sys; sys.path.insert(0, '../z5root/tools')
import axml
open('$OUT/AndroidManifest.xml','wb').write(
    axml.build_manifest(pkg='com.z5.sutest', label='SU Test', activity='.MainActivity'))
print('axml ok')
"

echo "== 4) 组包"
python3 - "$OUT" <<'PY'
import sys, os, zipfile
out = sys.argv[1]
apk = os.path.join(out, "unsigned.apk")
with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as z:
    z.write(os.path.join(out, "AndroidManifest.xml"), "AndroidManifest.xml")
    z.write(os.path.join(out, "dex", "classes.dex"), "classes.dex")
print("apk:", apk, os.path.getsize(apk), "bytes")
PY

echo "== 5) 签名"
cp "$OUT/unsigned.apk" "$OUT/signed.apk"
"$JARSIGNER" -keystore "$KEYSTORE" -storepass android -keypass android \
    -sigalg SHA256withRSA -digestalg SHA-256 \
    "$OUT/signed.apk" z5 2>&1 | tail -3

echo "== done"
ls -la "$OUT/signed.apk"
