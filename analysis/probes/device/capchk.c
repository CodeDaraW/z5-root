// capchk: 打印自己的 /proc/self/status 关键行到 /data/local/tmp/capchk.txt
// 用途: 验证 exec 之后 caps 是否存活 (本身不带任何 file capability)
static long sysc(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0"
        : "=r"(x0)
        : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");
    return x0;
}

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }

void _start(void)
{
    int f = (int)sysc(56, -100, (long)"/proc/self/status", 0, 0, 0, 0);
    char b[1024];
    long n = (f >= 0) ? sysc(63, f, (long)b, 1000, 0, 0, 0) : -1;
    if (f >= 0) sysc(57, f, 0, 0, 0, 0, 0);

    int o = (int)sysc(56, -100, (long)"/data/local/tmp/capchk.txt",
                      0x1 | 0x40 | 0x200, 0644, 0, 0);
    if (o < 0) sysc(93, 1, 0, 0, 0, 0, 0);
    if (n > 0) {
        for (long i = 0; i + 4 < n; i++) {
            int hit = 0;
            if (b[i]=='N'&&b[i+1]=='a'&&b[i+2]=='m'&&b[i+3]=='e') hit = 1;
            if (b[i]=='U'&&b[i+1]=='i'&&b[i+2]=='d'&&b[i+3]==':') hit = 1;
            if (b[i]=='G'&&b[i+1]=='i'&&b[i+2]=='d'&&b[i+3]==':') hit = 1;
            if (b[i]=='C'&&b[i+1]=='a'&&b[i+2]=='p'&&b[i+3]=='P') hit = 1;
            if (b[i]=='C'&&b[i+1]=='a'&&b[i+2]=='p'&&b[i+3]=='E') hit = 1;
            if (b[i]=='C'&&b[i+1]=='a'&&b[i+2]=='p'&&b[i+3]=='B') hit = 1;
            if (!hit) continue;
            long j = i;
            while (j < n && b[j] != '\n' && j < i + 40) { sysc(64, o, (long)&b[j], 1, 0, 0, 0); j++; }
            char nl = '\n';
            sysc(64, o, (long)&nl, 1, 0, 0, 0);
        }
    } else {
        const char *e = "nostat\n";
        sysc(64, o, (long)e, slen(e), 0, 0, 0);
    }
    sysc(57, o, 0, 0, 0, 0, 0);
    sysc(93, 0, 0, 0, 0, 0, 0);
}
