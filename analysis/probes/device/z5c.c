// z5c —— 极简 root 客户端
// 连抽象 unix socket "z5rootd", 把命令行发过去, 回显结果。
// 用法: z5c "id"   /   z5c "cat /data/misc/wifi/wpa_supplicant.conf"
// 连接 abstract socket 不需要任何权限, 普通 app 也能用。
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

static long slen(const char *s) { long n = 0; while (s[n]) n++; return n; }
static void say(const char *s) { sysc(64, 2, (long)s, slen(s), 0, 0, 0); }

struct zsun { unsigned short f; char p[110]; };

__asm__(
".global _start\n"
"_start:\n"
"   mov x0, sp\n"
"   bl  cstart\n"
"   b   .\n"
);

void cstart(unsigned long *sp)
{
    int argc = (int)sp[0];
    char **argv = (char **)&sp[1];

    if (argc < 2) {
        say("usage: z5c \"command\"\n");
        sysc(93, 2, 0, 0, 0, 0, 0);
    }

    static char buf[1500];
    int k = 0;
    for (int i = 1; i < argc; i++) {
        if (i > 1 && k < 1480) buf[k++] = ' ';
        char *p = argv[i];
        while (*p && k < 1480) buf[k++] = *p++;
    }
    buf[k] = 0;

    const char *nm = "z5rootd";
    int nl = 0; while (nm[nl]) nl++;

    int sk = (int)sysc(198, 1, 1, 0, 0, 0, 0);
    if (sk < 0) { say("z5c: socket fail\n"); sysc(93, 1, 0, 0, 0, 0, 0); }

    struct zsun sa;
    for (unsigned i = 0; i < sizeof(sa); i++) ((char *)&sa)[i] = 0;
    sa.f = 1;
    for (int i = 0; i < nl; i++) sa.p[1 + i] = nm[i];

    long r = sysc(203, sk, (long)&sa, 2 + 1 + nl, 0, 0, 0);
    if (r != 0) {
        say("z5c: root service not reachable (start the root app first)\n");
        sysc(93, 1, 0, 0, 0, 0, 0);
    }

    sysc(64, sk, (long)buf, k, 0, 0, 0);
    sysc(64, sk, (long)"\n", 1, 0, 0, 0);

    char b[4096];
    for (;;) {
        long n = sysc(63, sk, (long)b, sizeof(b), 0, 0, 0);
        if (n <= 0) break;
        long o = 0;
        while (o < n) {
            long w = sysc(64, 1, (long)(b + o), n - o, 0, 0, 0);
            if (w <= 0) break;
            o += w;
        }
    }
    sysc(57, sk, 0, 0, 0, 0, 0);
    sysc(93, 0, 0, 0, 0, 0, 0);
}
