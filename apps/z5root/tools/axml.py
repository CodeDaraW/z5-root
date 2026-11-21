#!/usr/bin/env python3
"""把文本清单编译成 Android 二进制 XML (AXML)。

没有 aapt/aapt2 时手工生成。格式要点:
  - 文件头 RES_XML_TYPE(0x0003)
  - 字符串池 (UTF-8 变体), 属性名必须排在最前面, 且顺序与资源映射表一致
  - 资源映射表 (0x0180): resmap[i] = 字符串 i 对应的 framework 资源 id,
    PackageParser 就是用 nameIndex 去查 resmap 得到 android:xxx 的真实 id
  - StartNamespace / StartElement / EndElement / EndNamespace

用法: axml.py out.xml.bin
"""
import struct
import sys

# ---- chunk types ----
RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_RESOURCE_MAP = 0x0180

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"
NO_ENTRY = 0xFFFFFFFF

# android framework 属性资源 id (自 API 1 起固定不变)
ATTR_IDS = {
    "label":            0x01010001,
    "name":             0x01010003,
    "hasCode":          0x0101000c,
    "debuggable":       0x0101000f,
    "exported":         0x01010010,
    "minSdkVersion":    0x0101020c,
    "versionCode":      0x0101021b,
    "versionName":      0x0101021c,
    "targetSdkVersion": 0x01010270,
    "allowBackup":      0x01010280,
}


class StringPool:
    def __init__(self):
        self.data = []
        self.index = {}

    def add(self, s):
        if s in self.index:
            return self.index[s]
        i = len(self.data)
        self.index[s] = i
        self.data.append(s)
        return i

    def encode(self):
        offsets = []
        blob = b""
        for s in self.data:
            offsets.append(len(blob))
            b = s.encode("utf-8")
            n16 = len(s)
            n8 = len(b)
            # UTF-8 变体: 长度字段 1 或 2 字节
            if n16 > 0x7F:
                blob += struct.pack("<H", (n16 >> 8) | 0x8000) + bytes([n16 & 0xFF])
            else:
                blob += bytes([n16])
            if n8 > 0x7F:
                blob += struct.pack("<H", (n8 >> 8) | 0x8000) + bytes([n8 & 0xFF])
            else:
                blob += bytes([n8])
            blob += b + b"\x00"
        while len(blob) % 4:
            blob += b"\x00"

        count = len(self.data)
        offs = b"".join(struct.pack("<I", o) for o in offsets)
        strings_start = 28 + len(offs)
        size = 28 + len(offs) + len(blob)
        head = struct.pack("<HHIIIIII", RES_STRING_POOL, 28, size,
                           count, 0, 0x100, strings_start, 0)
        return head + offs + blob


class Axml:
    def __init__(self):
        self.pool = StringPool()
        self.resmap = []
        self.body = b""
        self.attr_names = []

    def prepare_attrs(self, names):
        """属性名必须先入池, 且按资源 id 升序, 与 resmap 一一对应。"""
        uniq = sorted(set(names), key=lambda n: ATTR_IDS[n])
        for n in uniq:
            idx = self.pool.add(n)
            assert idx == len(self.resmap), "attr name must be at pool head"
            self.resmap.append(ATTR_IDS[n])
        self.attr_names = uniq

    def _chunk(self, ctype, hsize, payload):
        # payload 里已经含有 lineNumber/comment (属于 headerSize 覆盖的 16 字节头),
        # 所以总长 = hsize - 8 + len(payload)
        return struct.pack("<HHI", ctype, hsize, hsize - 8 + len(payload)) + payload

    def start_ns(self, prefix, uri, line=1):
        self.body += self._chunk(
            RES_XML_START_NAMESPACE, 16,
            struct.pack("<IIII", line, 0xFFFFFFFF,
                        self.pool.add(prefix), self.pool.add(uri)))

    def end_ns(self, prefix, uri, line=1):
        self.body += self._chunk(
            RES_XML_END_NAMESPACE, 16,
            struct.pack("<IIII", line, 0xFFFFFFFF,
                        self.pool.add(prefix), self.pool.add(uri)))

    def start(self, tag, attrs, line=1):
        """attrs: list of (ns_prefix_or_None, name, kind, value)
           kind: 'str' | 'int' | 'bool' | 'raw'"""
        chunk = struct.pack("<II", line, 0xFFFFFFFF)     # lineNumber, comment
        chunk += struct.pack("<II", NO_ENTRY, self.pool.add(tag))  # ns, name
        chunk += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)

        body = b""
        for (ns, name, kind, val) in attrs:
            # 注意: 属性里的 namespace 必须是完整 URI, 不是前缀.
            # PackageParser 对大部分属性是按资源 id 匹配的(所以填前缀也能过),
            # 但 parseIntent 里用的是 getAttributeValue(ANDROID_RESOURCES, "name")
            # —— 按 URI 字符串匹配, 填 "android" 就会失败 => MANIFEST_MALFORMED.
            ns_idx = NO_ENTRY if ns is None else self.pool.add(
                ANDROID_NS if ns == "android" else ns)
            nm_idx = self.pool.add(name)
            if kind == "str":
                raw = self.pool.add(val)
                body += struct.pack("<II", ns_idx, nm_idx)
                body += struct.pack("<I", raw)          # rawValue
                body += struct.pack("<HBBI", 8, 0, TYPE_STRING, raw)
            elif kind == "int":
                body += struct.pack("<II", ns_idx, nm_idx)
                body += struct.pack("<I", NO_ENTRY)
                body += struct.pack("<HBBI", 8, 0, TYPE_INT_DEC, val & 0xFFFFFFFF)
            elif kind == "bool":
                body += struct.pack("<II", ns_idx, nm_idx)
                body += struct.pack("<I", NO_ENTRY)
                body += struct.pack("<HBBI", 8, 0, TYPE_INT_BOOLEAN,
                                    0xFFFFFFFF if val else 0)
            else:
                raise ValueError(kind)
        self.body += self._chunk(RES_XML_START_ELEMENT, 16, chunk + body)

    def end(self, tag, line=1):
        self.body += self._chunk(
            RES_XML_END_ELEMENT, 16,
            struct.pack("<IIII", line, 0xFFFFFFFF, NO_ENTRY, self.pool.add(tag)))

    def build(self):
        pool = self.pool.encode()
        resmap = b""
        if self.resmap:
            resmap = struct.pack("<HHI", RES_XML_RESOURCE_MAP, 8,
                                 8 + 4 * len(self.resmap))
            resmap += b"".join(struct.pack("<I", r) for r in self.resmap)
        total = 8 + len(pool) + len(resmap) + len(self.body)
        head = struct.pack("<HHI", RES_XML, 8, total)
        return head + pool + resmap + self.body


def build_manifest(pkg="com.z5.root", label="Z5 Root", activity=".MainActivity",
                   variant="full"):
    a = Axml()
    a.prepare_attrs(["label", "name", "hasCode", "exported", "minSdkVersion",
                     "versionCode", "versionName", "targetSdkVersion",
                     "allowBackup", "debuggable"])
    a.start_ns("android", ANDROID_NS)
    a.start("manifest", [
        (None, "package", "str", pkg),
        ("android", "versionCode", "int", 1),
        ("android", "versionName", "str", "1.0"),
    ])
    for perm in ("android.permission.INTERNET",
                 "android.permission.RECEIVE_BOOT_COMPLETED"):
        a.start("uses-permission", [("android", "name", "str", perm)])
        a.end("uses-permission")
    a.start("uses-sdk", [
        ("android", "minSdkVersion", "int", 21),
        ("android", "targetSdkVersion", "int", 22),
    ])
    a.end("uses-sdk")
    if variant == "t1":
        a.end("manifest"); a.end_ns("android", ANDROID_NS); return a.build()
    app_attrs = [
        ("android", "label", "str", label),
        ("android", "hasCode", "bool", True),
        ("android", "allowBackup", "bool", False),
    ]
    if variant == "dbg":
        app_attrs.append(("android", "debuggable", "bool", True))
    a.start("application", app_attrs)
    if variant == "t2":
        a.end("application"); a.end("manifest"); a.end_ns("android", ANDROID_NS)
        return a.build()
    a.start("activity", [
        ("android", "name", "str", activity),
        ("android", "exported", "bool", True),
    ])
    if variant == "t3":
        a.end("activity"); a.end("application"); a.end("manifest")
        a.end_ns("android", ANDROID_NS)
        return a.build()
    a.start("intent-filter", [])
    a.start("action", [("android", "name", "str", "android.intent.action.MAIN")])
    a.end("action")
    a.start("category", [("android", "name", "str",
                          "android.intent.category.LAUNCHER")])
    a.end("category")
    a.end("intent-filter")
    a.end("activity")
    # ★ 开机广播: 只在"用户点过 root 但还没成功"时自动续跑一次
    #   (pending.txt 由 MainActivity 在点击时写入, 成功时删除)
    a.start("receiver", [
        ("android", "name", "str", ".BootReceiver"),
        ("android", "exported", "bool", True),
    ])
    a.start("intent-filter", [])
    a.start("action", [("android", "name", "str",
                        "android.intent.action.BOOT_COMPLETED")])
    a.end("action")
    a.end("intent-filter")
    a.end("receiver")
    a.end("application")
    a.end("manifest")
    a.end_ns("android", ANDROID_NS)
    return a.build()


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "AndroidManifest.xml"
    variant = sys.argv[2] if len(sys.argv) > 2 else "full"
    data = build_manifest(variant=variant)
    with open(out, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (out, len(data)))
