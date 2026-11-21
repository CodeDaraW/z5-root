package com.z5.root;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;

/**
 * Z5 一键 root
 *
 * v3 改动 (2026-11-08 18:20) —— 为了"不占多任务列表":
 *   实测 root 之后一进多任务界面 SystemUI 就会崩/卡死, 所以本 App 干脆
 *   **不留在任务栈里**: 点开 -> Toast 提示 -> 后台线程干活 -> finish() 立刻退出.
 *   任务结束即被系统回收, 不会出现在"最近任务"里.
 *
 *   代价: 跑的过程中看不到进度. 95 秒后重新打开本应用即可看到结果
 *   (会用 boot_id 判断"本次开机已跑过", 不会重复跑).
 *
 *   (上一版试过 FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS 重新拉起自己, 无效:
 *    同 affinity 的任务已存在时, 系统只会把旧任务提到前台, flag 被忽略.)
 */
public class MainActivity extends Activity {

    private TextView status;
    private Button btn;
    private volatile boolean busy = false;
    /** UAF 竞态失败率约 1/4~1/2; 失败不再重启手机, 所以最多原地重试 3 次 */
    private static final int MAX_TRY = 3;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(1);
        ll.setPadding(40, 90, 40, 40);

        btn = new Button(this);
        btn.setText("开始 ROOT");
        btn.setEnabled(false);
        ll.addView(btn);

        status = new TextView(this);
        status.setTextSize(12);
        status.setText("Z5 一键 root\n\n初始化...\n");
        ll.addView(status);

        setContentView(ll);

        Log.i("Z5", "onCreate done");

        final String dir = getFilesDir().getAbsolutePath();

        // ★ 取证: 把上一轮(可能已经 panic 重启)留下的现场搬到外部目录,
        //   这样 adb / 文件管理器都能直接看, 不需要 root 也不需要 run-as。
        //   必须在跑 exploit 之前做, 否则会被本轮覆盖。
        dumpPrev();

        // 取证模式: /data/local/tmp/z5hold 存在时只搬现场, 不跑 exploit
        // (adb 能创建这个文件, App 按全路径可读)
        if (new File("/data/local/tmp/z5hold").exists()
                || new File(dir + "/hold").exists()) {
            show("hold 模式: 只取证, 不执行 exploit。\n\n" + prevPath());
            return;
        }

        // 开机自动续跑 (BootReceiver 拉起, 带 auto=true)
        boolean auto = false;
        try { auto = getIntent().getBooleanExtra("auto", false); } catch (Throwable t) { }

        if (auto && !alreadyRanThisBoot()) {
            show("开机自动续跑 root…\n\n"
                    + "(你之前点过 ROOT 但没成功, 失败会重启, 已自动接着跑)\n");
            fire();
        } else if (alreadyRanThisBoot()) {
            // 本次开机已经跑过: 只做自检, 不再跑
            btn.setEnabled(true);
            btn.setText("重跑");
            btn.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) { fire(); }
            });
            show("本次开机已经跑过一次 exploit。\n正在读取状态...\n");
            new Thread(new Runnable() {
                public void run() {
                    String d = diag();
                    show("本次开机已经跑过一次 exploit。\n"
                            + "如果上次成功, /mnt/su 现在应该还在, 不用再跑。\n\n"
                            + d
                            + "\n如果上面显示已经成功, 点“重跑”不会真的重跑 ——\n"
                            + "程序会先检查 /mnt/su 能不能 exec 出 uid=0, 能用就直接返回。\n"
                            + "只有在 root 丢失时才真正重建 UAF(那一步有小概率触发内核\n"
                            + "panic 黑屏重启, 重启后 App 会自动接着跑, 不用你操作)。\n");
                }
            }).start();
        } else if (runningThisBoot(dir)) {
            // 上一次还在跑 (或异常中断)
            btn.setEnabled(true);
            btn.setText("重跑");
            btn.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) { fire(); }
            });
            show("上一次的 root 还在进行中 (约 25~50 秒)。\n\n"
                    + "请等一会儿重新打开本应用查看结果; 如果一直没有结果,\n"
                    + "点上面的重跑即可 (不会重启手机)。\n");
        } else {
            // 真正的一键: 用户点了 = 授权。写 pending 表示"这次授权还没兑现",
            // 失败导致重启时 BootReceiver 会接着跑 (最多 3 次, 成功后删掉)。
            writeFile(dir + "/pending.txt", "1");
            try {
                Toast.makeText(this,
                        "已开始 root，约 20~80 秒，请留在此页面。",
                        Toast.LENGTH_LONG).show();
            } catch (Throwable t) {
                Log.i("Z5", "toast fail " + t);
            }
            fire();
            // ★ 2026-11-11: 不再"立刻 finish 退到后台"。
            //   原来那样做是为了避免多任务列表里留着本 App (root 之后进 recents
            //   会让 SystemUI 崩), 但代价是 work() 的后台线程随进程一起被回收,
            //   自动重试根本跑不完 (实测 3 次重试一次都没发生)。
            //   现在改成: 跑的过程中保持 Activity 在前台 (用户能看到进度),
            //   work() 结束后再 finishAndRemoveTask() —— 只要几秒, 窗口很短。
            show("正在准备…\n");
        }
    }

    private void show(final String s) {
        runOnUiThread(new Runnable() {
            public void run() { status.setText(s); }
        });
    }

    /** 上一轮现场的外部副本目录 (adb 可读, 无需 root) */
    private String prevDir() {
        File ext = null;
        try { ext = getExternalFilesDir(null); } catch (Throwable t) { }
        if (ext == null) ext = new File("/storage/emulated/0/Android/data/com.z5.root/files");
        return ext.getAbsolutePath() + "/prev";
    }

    private String prevPath() { return prevDir(); }

    /** 把 files/ 下的关键现场文件复制到外部 prev/ 目录, 并写一份 meta */
    private void dumpPrev() {
        try {
            String src = getFilesDir().getAbsolutePath();
            String dst = prevDir();
            File d = new File(dst);
            d.mkdirs();
            String[] names = {"step.txt", "out.txt", "rep.bin", "running.txt", "lastboot.txt",
                              "att.txt", "pending.txt"};
            StringBuilder meta = new StringBuilder();
            meta.append("dump at boot_id=").append(bootId()).append('\n');
            meta.append("host uptime=").append(cat("/proc/uptime").trim()).append('\n');
            for (String n : names) {
                File f = new File(src, n);
                long len = f.length();
                boolean ok = copyFile(f, new File(d, n));
                meta.append(n).append(": ").append(len).append(" bytes copy=")
                    .append(ok ? "ok" : "fail").append('\n');
            }
            writeFile(dst + "/meta.txt", meta.toString());
            Log.i("Z5", "dumpPrev -> " + dst + "\n" + meta);
        } catch (Throwable t) {
            Log.e("Z5", "dumpPrev fail", t);
        }
    }

    private boolean copyFile(File src, File dst) {
        if (!src.exists()) return false;
        FileInputStream in = null;
        FileOutputStream out = null;
        try {
            in = new FileInputStream(src);
            out = new FileOutputStream(dst);
            byte[] buf = new byte[16384];
            int n;
            long total = 0;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                total += n;
                if (total > 1024 * 1024) break;
            }
            out.flush();
            out.close();
            out = null;
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (in != null) in.close(); } catch (Throwable t) { }
            try { if (out != null) out.close(); } catch (Throwable t) { }
        }
    }

    private void fire() {
        if (busy) return;
        busy = true;
        btn.setEnabled(false);
        Log.i("Z5", "fire()");
        final MainActivity self = this;
        new Thread(new Runnable() {
            public void run() { self.work(); }
        }).start();
    }

    private void work() {
        String dir = getFilesDir().getAbsolutePath();
        String exe = dir + "/z5root";

        // ★★★ 2026-11-11: 已经是 root 就直接收工, 绝不重建 UAF。
        //   重跑的全部风险都集中在"重建 UAF"这一步 (建立过程中 LEAVE 那一下
        //   可能触发内核 panic)。既然 /mnt/su 已经能 exec 出 uid=0, 再跑一遍
        //   纯属自找风险 —— 用户误点一次不该换来一次黑屏重启。
        //   注意: 重启后 SELinux 回到 Enforcing, rootReady() 会变回 false,
        //   那时点按钮才会真的重跑, 逻辑正确。
        if (rootReady()) {
            writeFile(dir + "/lastboot.txt", bootId());
            try { new File(dir + "/pending.txt").delete(); } catch (Throwable t) { }
            try { new File(dir + "/running.txt").delete(); } catch (Throwable t) { }
            String s = "★ 已经是 root 状态。\n\n"
                    + "本次不再重建 UAF —— 重建过程有小概率触发内核 panic,\n"
                    + "已经能用了就没必要冒这个险。\n"
                    + "如果 su 用不了(例如刚重启过), 关掉本应用再点一次即可。\n\n"
                    + diag();
            Log.i("Z5", s);
            show(s);
            busy = false;
            runOnUiThread(new Runnable() {
                public void run() { btn.setEnabled(true); btn.setText("重跑"); }
            });
            leave();
            return;
        }

        try {
            writeFile(dir + "/running.txt", bootId());
            drop("z5root", exe);
            drop("su", dir + "/su");
            run("/system/bin/chmod", "755", exe);
            writeFile(dir + "/lastboot.txt", bootId());
        } catch (Throwable t) {
            Log.e("Z5", "prepare fail", t);
            show("准备失败: " + t);
        }

        // ===== ★★★ 2026-11-11 08:05: 先等 15 秒, 再动内核 =====
        //
        // 为什么必须等 (实测出来的):
        //   用户点开 App 时, PackageManager 只是在**内存里**把本包标成
        //   "已启动" (stopped=false / notLaunched=false), 真正写进
        //   /data/system/packages.xml 有约 10 秒的延迟。
        //   而 exploit 建立 UAF 时 LEAVE 那一步有 ~40% 概率 panic 重启 ——
        //   如果 panic 发生在写盘之前, 这次"已启动"就丢了, 开机后包还是
        //   stopped=true, 系统**不投递 BOOT_COMPLETED**, BootReceiver 不会
        //   被拉起, "重启后自动接着跑"这条救命链就断了。
        //
        //   实测对照 (同一台机器, 安装后立刻点图标):
        //     5 秒后重启  -> 重启后 stopped=true  notLaunched=true   ← 断链
        //    15 秒后重启 -> 重启后 stopped=false notLaunched=false   ← 正常
        //
        //   15 秒的代价换来的是"点一次之后, 无论崩多少次都能自己接上",
        //   很值。用户看到的是倒计时, 不会以为卡住。
        for (int i = 0; i < 5; i++) {
            final int left = 15 - i * 3;
            show("正在准备…\n\n" + left + " 秒后开始。\n"
                    + "(这一步不能省: 让系统先记住你启动过本应用,\n"
                    + " 万一后面崩溃重启, 开机才能自动接着跑。)");
            try { Thread.sleep(3000); } catch (Throwable t) { }
        }

        // ★ 2026-11-11: 自动重试。
        //   exploit 里的 UAF 建链有约 1/4~1/2 概率失败(竞态)。
        //   现在 exploit 第一步就会把 panic_on_oops 减成 0, 所以失败只会
        //   杀掉那个进程, 手机不会重启 —— 于是可以原地重试, 不需要用户重启手机。
        boolean ok = false;
        int used = 0;
        for (int att = 1; att <= MAX_TRY && !ok; att++) {
            used = att;
            writeFile(dir + "/att.txt", "start attempt " + att + " / " + MAX_TRY + "\n");
            show("第 " + att + " / " + MAX_TRY + " 次尝试…\n\n"
                    + "正在建立 UAF，约 25 秒。\n");
            try {
                // exploit 拿到 root 后不会退出 (UAF 之后故意 hang), 所以只起进程不等待
                new ProcessBuilder("/system/bin/sh", "-c",
                        "cd " + dir + " && exec ./z5root > out.txt 2>&1").start();
                Log.i("Z5", "exploit started, attempt " + att);
            } catch (Throwable t) {
                Log.e("Z5", "spawn fail", t);
            }

            for (int i = 1; i <= 16; i++) {
                try { Thread.sleep(3000); } catch (Throwable t) { }
                if (rootReady()) { ok = true; break; }
                show("第 " + att + " / " + MAX_TRY + " 次尝试   " + (i * 3) + "s\n\n"
                        + tail(dir + "/out.txt", 12)
                        + "\n(失败会自动重试; 若中途黑屏重启, 开机后会自动接着跑)\n");
            }
            Log.i("Z5", "attempt " + att + " end, ok=" + ok);
            writeFile(dir + "/att.txt", "attempt " + att + " end, ok=" + ok + "\n");
            // 每次尝试结束都把现场搬到外部目录, 这样即使后面失败/进程被杀,
            // adb 也能直接读到这一步的 rep.bin / out.txt
            dumpPrev();
            if (!ok) {
                try { Thread.sleep(2500); } catch (Throwable t) { }
            }
        }

        // 成功了: 兑现了这次授权, 之后开机不再自动跑
        if (ok) {
            try { new File(dir + "/pending.txt").delete(); } catch (Throwable t) { }
        }

        // 成功后【故意】把 panic_on_oops 留在 0:
        //   exploit 拿到的 UAF 现场会一直挂着 (进程 hang 着不退出), 万一之后
        //   内核碰一下就 oops, 恢复成 1 会立刻重启手机 —— 那正是用户最不想要的。
        //   留在 0 的话, 这类残留 fault 最多杀掉一个进程, 手机继续用。
        //   重启一次即可恢复内核原厂默认值 (1)。

        String done = (ok ? "★ 成功: root 已就位\n\n" : "× 三次都没成功。\n"
                        + "可以再点一次重跑，或重启手机后重新点。\n\n")
                + diag()
                + "\n-- rep.bin 尾部 --\n" + tail(dir + "/rep.bin", 22);
        Log.i("Z5", "RESULT\n" + done);
        show(done);
        try { new File(dir + "/running.txt").delete(); } catch (Throwable t) { }
        busy = false;
        runOnUiThread(new Runnable() {
            public void run() {
                btn.setEnabled(true);
                btn.setText("重跑");
            }
        });

        // 结果在屏幕上留 6 秒, 然后把本任务从最近任务里删掉
        // (root 在位时进多任务界面会让 SystemUI 崩, 这是早期踩到的坑)
        leave();
    }

    /** 结果在屏幕上留 6 秒, 然后把本任务从最近任务列表里移除 */
    private void leave() {
        try { Thread.sleep(6000); } catch (Throwable t) { }
        runOnUiThread(new Runnable() {
            public void run() {
                try { finishAndRemoveTask(); } catch (Throwable t) { finish(); }
            }
        });
    }

    /** /mnt/su 已就位且有 s 位, 并且真的能 exec 出 uid=0 */
    private boolean rootReady() {
        String ls = run("/system/bin/ls", "-l", "/mnt/su");
        if (ls.indexOf("rws") < 0) return false;
        return suId().indexOf("uid=0") >= 0;
    }

    /** 现状自检: /mnt/su 是否存在 + s 位 + su -c id 实测 + exploit 自检 id.txt */
    private String diag() {
        StringBuilder sb = new StringBuilder();
        String lsout = run("/system/bin/ls", "-l", "/mnt/su");
        boolean ok = lsout.indexOf("rws") >= 0;
        sb.append(ok ? "★ 成功: su 已就位\n" : "× 未成功: /mnt/su 缺失或无 s 位\n");
        sb.append(lsout);
        sb.append("\n-- su -c id --\n").append(suId());
        // exploit 自己在 euid=0 下 exec 出来的自检结果 (id + caps)
        String idf = getFilesDir().getAbsolutePath() + "/id.txt";
        String ids = cat(idf);
        if (!ids.startsWith("(read fail")) {
            sb.append("\n-- id.txt --\n").append(ids);
        }
        return sb.toString();
    }

    /** 在独立线程里跑 su -c id, 最多等 8 秒; stderr 合并进来, 便于排查 */
    private String suId() {
        final StringBuilder out = new StringBuilder();
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    Process p = new ProcessBuilder("/mnt/su", "-c", "id")
                            .redirectErrorStream(true).start();
                    java.io.BufferedReader r = new java.io.BufferedReader(
                            new java.io.InputStreamReader(p.getInputStream()));
                    String line;
                    int lines = 0;
                    while ((line = r.readLine()) != null) {
                        out.append(line).append('\n');
                        lines++;
                        if (lines > 40) break;
                    }
                    int rc = p.waitFor();
                    out.append("[exit ").append(rc).append("]\n");
                } catch (Throwable e) {
                    out.append("ERR ").append(e.toString());
                }
            }
        });
        t.setDaemon(true);
        t.start();
        try { t.join(8000); } catch (Throwable e) { }
        return out.length() == 0 ? "(8 秒内无输出, 视为失败)\n" : out.toString();
    }

    private String run(String... cmd) {
        StringBuilder sb = new StringBuilder();
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            java.io.BufferedReader r =
                    new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            p.waitFor();
        } catch (Throwable t) {
            sb.append("ERR ").append(t.toString()).append('\n');
        }
        return sb.toString();
    }

    /**
     * 把 assets 里的可执行文件落盘。
     *
     * ★ 2026-11-11 修: 原来是直接 FileOutputStream(dst) 覆盖写。
     *   同一个 boot 内"重跑"时, 旧的 ./z5root 还在执行, 覆盖会拿到
     *   ETXTBSY (Text file busy) —— work() 直接在解包这一步抛异常,
     *   表现就是"点了重跑但什么都没发生"。
     *   改成写 dst+".new" 再 rename 覆盖: 运行中的 inode 不会被碰,
     *   rename 是原子的, 也不受 ETXTBSY 限制。
     */
    private void drop(String asset, String dst) throws Exception {
        File tmp = new File(dst + ".new");
        InputStream in = getAssets().open(asset);
        FileOutputStream out = new FileOutputStream(tmp);
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        out.close();
        in.close();
        if (!tmp.renameTo(new File(dst))) {
            throw new Exception("rename fail: " + tmp + " -> " + dst);
        }
        Log.i("Z5", "drop " + asset + " -> " + dst);
    }

    private void writeFile(String path, String s) {
        try {
            FileOutputStream o = new FileOutputStream(path);
            o.write(s.getBytes("UTF-8"));
            o.close();
        } catch (Throwable t) { }
    }

    private String bootId() {
        try {
            FileInputStream in = new FileInputStream("/proc/sys/kernel/random/boot_id");
            byte[] b = new byte[80];
            int n = in.read(b);
            in.close();
            if (n <= 0) return "unknown";
            return new String(b, 0, n, "UTF-8").trim();
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private boolean alreadyRanThisBoot() {
        String cur = bootId();
        if ("unknown".equals(cur)) return false;
        String prev = cat(getFilesDir().getAbsolutePath() + "/lastboot.txt").trim();
        return cur.equals(prev);
    }

    /** 上一次的 root 是否"本次开机"还在跑.
     *  必须比对 boot_id: 否则上一轮 panic 留下的 running.txt 会让 App 永远
     *  以为"还在跑", 既不再跑, 又把界面挂在多任务里 (2026-11-08 18:22 踩到). */
    private boolean runningThisBoot(String dir) {
        String cur = bootId();
        if ("unknown".equals(cur)) return false;
        return cur.equals(cat(dir + "/running.txt").trim());
    }

    private String tail(String path, int n) {
        String s = cat(path);
        if (s.startsWith("(read fail")) return s;
        String[] ls = s.split("\n");
        int st = ls.length > n ? ls.length - n : 0;
        StringBuilder sb = new StringBuilder();
        for (int i = st; i < ls.length; i++) {
            sb.append(ls[i]).append('\n');
        }
        return sb.toString();
    }

    private String cat(String path) {
        try {
            FileInputStream in = new FileInputStream(path);
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) {
                bo.write(buf, 0, n);
            }
            in.close();
            String s = new String(bo.toByteArray(), "UTF-8");
            return s.replace('\u0000', ' ');
        } catch (Throwable t) {
            return "(read fail: " + t + ")";
        }
    }
}
