#!/usr/bin/env python3
import socket,struct,sys
def rpc(s,a1,payload,a0=0,ver=1):
    s.sendall(struct.pack(">I",len(payload)+9)+bytes([ver])+struct.pack(">I",a0)+struct.pack(">I",a1)+payload)
    h=s.recv(4)
    if not h: raise IOError("eof")
    ln=struct.unpack(">I",h)[0]; b=b""
    while len(b)<ln:
        c=s.recv(ln-len(b))
        if not c: raise IOError("eof2")
        b+=c
    return b
s=socket.create_connection(("127.0.0.1",19999),timeout=10)
rpc(s,0,bytes([1,1]))
found=[]; existing=[]
lo,hi=int(sys.argv[1],0),int(sys.argv[2],0)
for u in range(lo,hi):
    try:
        b=rpc(s,2,struct.pack(">I",u))
    except Exception as e:
        print("scan aborted at",hex(u),e); break
    if len(b)>=8:
        st,sz=struct.unpack(">II",b[:8])
        if st==0 and sz>0:
            existing.append((u,sz))
print(f"existing units in [{lo:#x},{hi:#x}): {len(existing)}")
big=[(u,s) for u,s in existing if s>=8]
print("with size>=8:",len(big))
for u,sz in big:
    try:
        b=rpc(s,3,struct.pack(">I",u))
    except Exception as e:
        print(" read fail",hex(u),e); break
    if len(b)<12: continue
    st=struct.unpack(">I",b[4:8])[0]; ln=struct.unpack(">I",b[8:12])[0]
    data=b[12:12+ln]
    if ln>=2 and data[:2]==b"\x1a\xce":
        print(f"  *** 1ACE BOOTCONFIG at unit {u:#06x} len={ln}")
        found.append((u,data))
    elif b"ROOTING" in data or b"HOP_ID" in data:
        print(f"  *** CONFIG TEXT at unit {u:#06x} len={ln}: {data[:60]!r}")
if found:
    u,d=found[0]
    import os
    REPO=os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..'))
    out=os.path.join(REPO,'artifacts','ta','bootconfig_misc.bin')
    open(out,"wb").write(d)
    print(f"saved {len(d)} bytes from unit {u:#06x} -> {out}")
s.close()
