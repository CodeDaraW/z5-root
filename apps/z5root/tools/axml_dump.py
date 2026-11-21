#!/usr/bin/env python3
"""极简 AXML 解析器, 只用来验证自己生成的文件结构是否自洽。"""
import struct
import sys

RES_STRING_POOL = 0x0001
RES_XML_START_NS = 0x0100
RES_XML_END_NS = 0x0101
RES_XML_START = 0x0102
RES_XML_END = 0x0103
RES_XML_RESMAP = 0x0180


def parse_pool(b, off):
    ctype, hsize, size = struct.unpack_from("<HHI", b, off)
    count, style_count, flags, sstart, ststart = struct.unpack_from("<IIIII", b, off + 8)
    utf8 = bool(flags & 0x100)
    offs = struct.unpack_from("<%dI" % count, b, off + hsize)
    base = off + sstart
    out = []
    for o in offs:
        p = base + o
        if utf8:
            n16 = b[p]; p += 1
            if n16 & 0x80:
                n16 = ((n16 & 0x7F) << 8) | b[p]; p += 1
            n8 = b[p]; p += 1
            if n8 & 0x80:
                n8 = ((n8 & 0x7F) << 8) | b[p]; p += 1
            s = b[p:p + n8].decode("utf-8", "replace")
        else:
            n16 = struct.unpack_from("<H", b, p)[0]; p += 2
            if n16 & 0x8000:
                n16 = ((n16 & 0x7FFF) << 16) | struct.unpack_from("<H", b, p)[0]; p += 2
            s = b[p:p + n16 * 2].decode("utf-16-le", "replace")
        out.append(s)
    return out, size, utf8


def dump(path):
    b = open(path, "rb").read()
    ctype, hsize, size = struct.unpack_from("<HHI", b, 0)
    print("file type=0x%04x hsize=%d size=%d (actual %d)" % (ctype, hsize, size, len(b)))
    pool, psize, utf8 = parse_pool(b, 8)
    print("pool: %d strings, utf8=%s" % (len(pool), utf8))
    off = 8 + psize
    resmap = []
    depth = 0
    while off < size:
        t, hs, sz = struct.unpack_from("<HHI", b, off)
        if sz == 0:
            print("!! zero-size chunk at %d" % off)
            break
        if t == RES_XML_RESMAP:
            n = (sz - 8) // 4
            resmap = list(struct.unpack_from("<%dI" % n, b, off + 8))
            print("resmap: %d ids: %s" % (n, ", ".join("0x%08x" % r for r in resmap)))
        elif t == RES_XML_START_NS:
            line, cmt, pre, uri = struct.unpack_from("<IIII", b, off + hs)
            print("  <ns %s=%s>" % (pool[pre], pool[uri]))
        elif t == RES_XML_END_NS:
            line, cmt, pre, uri = struct.unpack_from("<IIII", b, off + hs)
            print("  </ns %s>" % pool[pre])
        elif t == RES_XML_START:
            line, cmt, ns, name = struct.unpack_from("<IIII", b, off + hs)
            astart, asize, acount, i1, i2, i3 = struct.unpack_from("<HHHHHH", b, off + hs + 8)
            attrs = []
            ap = off + hs + 8 + astart
            for i in range(acount):
                ans, anm, raw = struct.unpack_from("<III", b, ap)
                vs, r0, dt, data = struct.unpack_from("<HBBI", b, ap + 12)
                nm = pool[anm] if anm < len(pool) else "?%d" % anm
                rid = resmap[anm] if anm < len(resmap) else None
                if dt == 0x03:
                    val = repr(pool[data]) if data < len(pool) else "?%d" % data
                elif dt == 0x12:
                    val = str(bool(data))
                else:
                    val = "0x%x" % data
                if ans == 0xFFFFFFFF:
                    nsname = ""
                else:
                    nsname = pool[ans] + ":" if ans < len(pool) else "?:"
                attrs.append("%s%s(%s)=%s" % (nsname, nm, "0x%08x" % rid if rid else "raw", val))
                ap += asize
            print("  " * (depth + 1) + "<%s %s>" % (pool[name], " ".join(attrs)))
            depth += 1
        elif t == RES_XML_END:
            line, cmt, ns, name = struct.unpack_from("<IIII", b, off + hs)
            depth -= 1
            print("  " * (depth + 1) + "</%s>" % pool[name])
        else:
            print("?? chunk type 0x%04x at %d size %d" % (t, off, sz))
        off += sz


if __name__ == "__main__":
    dump(sys.argv[1])
