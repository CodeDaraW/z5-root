// su —— Z5 root 客户端 / 直接提权 (aarch64 freestanding)
//
// 用法:
//   su                     -> 交互式 root shell
//   su -c "cmd"            -> 执行一条命令
//   su -c cmd arg1 arg2    -> 同上, 多余参数拼进命令
//
// 两条路径:
//   A. 直接: setresuid(0,0,0) 之后如果 capset 拿到了非空 permitted, 就地
//      exec /system/bin/sh。适用于 capability bounding set 完整的调用者
//      (init/zygote 系)。
//   B. 代理: 否则 (典型是 app, zygote 把 app 的 CapBnd 收成了 0) 连抽象
//      unix socket "z5rootd" —— 那是 exploit 提权后 fork 出来的常驻 root
//      服务, 它 exec 出来的每个进程都是 uid=0 + caps 满值。
//
// 编译:
//   clang -target aarch64-none-elf -c -O2 -ffreestanding -fno-builtin \
//     -fno-stack-protector -fno-asynchronous-unwind-tables -nostdlib \
//     -mno-outline-atomics -w su.c -o su.o
//   python3 ../../../analysis/probes/device/mkelf.py su.o su

typedef unsigned long u64;

static inline long sysc(long n, long a, long b, long c, long d, long e, long f)
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

#define setresuid_(a,b,c) sysc(147, a, b, c, 0, 0, 0)
#define setresgid_(a,b,c) sysc(149, a, b, c, 0, 0, 0)
#define execve_(p, a, e)  sysc(221, (long)(p), (long)(a), (long)(e), 0, 0, 0)
#define write_(fd, b, n)  sysc(64, fd, (long)(b), n, 0, 0, 0)
#define read_(fd, b, n)   sysc(63, fd, (long)(b), n, 0, 0, 0)
#define close_(fd)        sysc(57, fd, 0, 0, 0, 0, 0)
#define exit_(c)          sysc(93, c, 0, 0, 0, 0, 0)
#define getuid_()         sysc(174, 0, 0, 0, 0, 0, 0)
#define fork_()           sysc(220, 17, 0, 0, 0, 0, 0)

static long slen(const char *s) { long n = 0; while (s[n]) n++; return n; }
static void say(const char *s) { write_(2, s, slen(s)); }

struct zsun { unsigned short f; char p[110]; };

__asm__(
".global _start\n"
"_start:\n"
"   mov x0, sp\n"
"   bl  cstart\n"
"   b   .\n"
);

// ---- 读 /proc/self/status 的 CapPrm, 判断这次提权有没有实际拿到权限 ----
static int cap_prm_nonzero(void)
{
    int f = (int)sysc(56, -100, (long)"/proc/self/status", 0, 0, 0, 0);
    if (f < 0) return 0;
    char b[1024];
    long n = read_(f, b, 1000);
    close_(f);
    if (n <= 0) return 0;
    for (long i = 0; i + 8 < n; i++) {
        if (b[i]=='C'&&b[i+1]=='a'&&b[i+2]=='p'&&b[i+3]=='P'&&
            b[i+4]=='r'&&b[i+5]=='m'&&b[i+6]==':') {
            long j = i + 7;
            while (j < n && (b[j] == ' ' || b[j] == '\t')) j++;
            long v = 0; int any = 0;
            while (j < n) {
                char c = b[j];
                int d = -1;
                if (c >= '0' && c <= '9') d = c - '0';
                else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                if (d < 0) break;
                v = (v << 4) | d; any = 1; j++;
            }
            return any && v != 0;
        }
    }
    return 0;
}

static int zconnect(void)
{
    const char *nm = "z5rootd";
    int nl = 0; while (nm[nl]) nl++;
    int sk = (int)sysc(198, 1, 1, 0, 0, 0, 0);
    if (sk < 0) return -1;
    struct zsun sa;
    for (unsigned i = 0; i < sizeof(sa); i++) ((char *)&sa)[i] = 0;
    sa.f = 1;
    for (int i = 0; i < nl; i++) sa.p[1 + i] = nm[i];
    long r = sysc(203, sk, (long)&sa, 2 + 1 + nl, 0, 0, 0);
    if (r != 0) { close_(sk); return -2; }
    return sk;
}

// 通过 root 服务跑一条命令, 回显
static int proxy_cmd(int sk, const char *cmd)
{
    if (sk < 0) {
        say("su: 没有 root。请先把 Z5 Root 应用跑一次。\n");
        return 1;
    }
    write_(sk, cmd, slen(cmd));
    write_(sk, "\n", 1);
    char b[4096];
    for (;;) {
        long n = read_(sk, b, sizeof(b));
        if (n <= 0) break;
        long o = 0;
        while (o < n) {
            long w = write_(1, b + o, n - o);
            if (w <= 0) break;
            o += w;
        }
    }
    close_(sk);
    return 0;
}

// 交互式: 双向转发
static int proxy_shell(int sk)
{
    if (sk < 0) {
        say("su: 没有 root。请先把 Z5 Root 应用跑一次。\n");
        return 1;
    }
    write_(sk, "exec /system/bin/sh\n", 20);
    long p = fork_();
    if (p == 0) {
        char b[1024];
        for (;;) {
            long n = read_(0, b, sizeof(b));
            if (n <= 0) break;
            write_(sk, b, n);
        }
        sysc(210, sk, 1, 0, 0, 0, 0);          // shutdown(sk, SHUT_WR)
        for (;;) sysc(101, 0, 0, 0, 0, 0, 0);  // nanosleep 空转
    }
    char b[2048];
    for (;;) {
        long n = read_(sk, b, sizeof(b));
        if (n <= 0) break;
        long o = 0;
        while (o < n) {
            long w = write_(1, b + o, n - o);
            if (w <= 0) break;
            o += w;
        }
    }
    return 0;
}

void cstart(unsigned long *sp)
{
    int argc = (int)sp[0];
    char **argv = (char **)&sp[1];
    char **envp = argv + argc + 1;

    // ---- 路径 B 优先: 常驻 root 服务 (给的是真 root + 满 caps) ----
    int sk = zconnect();

    // ---- 路径 A 兜底: 就地提权 (调用者 bounding set 完整时可用) ----
    setresgid_(0, 0, 0);
    setresuid_(0, 0, 0);

    int strong = 0;
    if (getuid_() == 0) {
        struct { unsigned int version; int pid; } hdr;
        struct { unsigned int eff, prm, inh; } dat[2];
        hdr.version = 0x20080522;      // _LINUX_CAPABILITY_VERSION_3
        hdr.pid = 0;
        dat[0].eff = 0xffffffffu; dat[0].prm = 0xffffffffu; dat[0].inh = 0;
        dat[1].eff = 0x000001ffu; dat[1].prm = 0x000001ffu; dat[1].inh = 0;
        sysc(91, (long)&hdr, (long)dat, 0, 0, 0, 0);   // capset
        strong = cap_prm_nonzero();
    }

    static char sh[] = "/system/bin/sh";

    // ---- su -c "cmd" ----
    if (argc >= 3 && argv[1][0] == '-' && argv[1][1] == 'c' && argv[1][2] == 0) {
        if (strong && sk < 0) {
            static char *av[8];
            av[0] = sh;
            av[1] = (char *)"-c";
            int k = 2;
            for (int i = 2; i < argc && k < 7; i++) av[k++] = argv[i];
            av[k] = 0;
            execve_(sh, av, envp);
        }
        // 把参数拼成一条命令
        static char buf[1500];
        int k = 0;
        for (int i = 2; i < argc; i++) {
            if (i > 2 && k < 1480) buf[k++] = ' ';
            char *p = argv[i];
            while (*p && k < 1480) buf[k++] = *p++;
        }
        buf[k] = 0;
        exit_(proxy_cmd(sk, buf));
    }

    // ---- 裸 su ----
    if (strong && sk < 0) {
        static char *av[2];
        av[0] = sh;
        av[1] = 0;
        execve_(sh, av, envp);
        say("su: 直接 exec 失败, 改走 root 服务\n");
    }
    exit_(proxy_shell(sk));
}
