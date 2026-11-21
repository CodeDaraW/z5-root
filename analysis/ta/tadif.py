#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TAD 客户端：经 adb forward 连 /dev/socket/tad。只读封装。
协议（大端）: [u32 len+9][u8 ver][u32 a0][u32 op][payload]
  ver=1, op: 0=open 2=getsize 3=read 4=write
回包: [u32 total][body]，getsize body=[st][size]，read body=[st][len][data]
"""
import socket, struct

HOST, PORT = "127.0.0.1", 19999
ST = {0:"Success",1:"General error",2:"Unsupported version",3:"Memory error",
      4:"Unit not found",5:"Operation not allowed",6:"Trimarea not valid",
      7:"Invalid argument",8:"Flash error",9:"Not implemented",10:"Config error"}

class Tad:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=6)
    def _rd(self, n):
        b = b""
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c: raise IOError("eof %d/%d" % (len(b), n))
            b += c
        return b
    def _hdr(self):
        return struct.unpack(">I", self._rd(4))[0]
    def _send(self, op, payload=b"", a0=0, ver=1):
        self.s.sendall(struct.pack(">I", len(payload)+9) + bytes([ver])
                       + struct.pack(">I", a0) + struct.pack(">I", op) + payload)
    def open(self, mode=1):
        self._send(0, bytes([mode, 1]))
        self._hdr(); return struct.unpack(">I", self._rd(4))[0]
    def getsize(self, unit):
        self._send(2, struct.pack(">I", unit))
        total = self._hdr()
        body = self._rd(total)
        st = struct.unpack(">I", body[:4])[0]
        sz = struct.unpack(">I", body[4:8])[0] if len(body) >= 8 else None
        return st, (sz if st == 0 else None)
    def read(self, unit):
        self._send(3, struct.pack(">I", unit))
        total = self._hdr()
        st = struct.unpack(">I", self._rd(4))[0]
        if st != 0: return st, None
        ln = struct.unpack(">I", self._rd(4))[0]
        return 0, self._rd(ln)
    def close(self):
        try: self.s.close()
        except Exception: pass
