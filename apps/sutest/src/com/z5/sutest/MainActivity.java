package com.z5.sutest;

import android.app.Activity;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.InputStreamReader;

/**
 * 第三方 App 视角的验证器。
 *
 * 本 App 完全不参与 exploit，只是像任何一个普通应用那样
 *   Runtime.exec(new String[]{"/mnt/su","-c",...})
 * 来调用 root。用来证明「root 可以给其他 app 使用」。
 *
 * v2: 加看门狗 (每条命令 6 秒上限) + 结果同时写进 files/r.txt，
 *     这样即使 UI 卡住/屏幕熄灭也能取证。
 */
public class MainActivity extends Activity {

    private TextView tv;
    private final StringBuilder log = new StringBuilder();

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(1);
        ll.setPadding(40, 90, 40, 40);
        tv = new TextView(this);
        tv.setTextSize(11);
        tv.setText("SU Test\n\nrunning...\n");
        ll.addView(tv);
        sv.addView(ll);
        setContentView(sv);

        Log.i("SUTEST", "onCreate");

        new Thread(new Runnable() {
            public void run() {
                buildReport();
                final String s = log.toString();
                dump(s);
                Log.i("SUTEST", "REPORT\n" + s);
                runOnUiThread(new Runnable() {
                    public void run() { tv.setText(s); }
                });
            }
        }).start();
    }

    private void buildReport() {
        line("pkg = com.z5.sutest");
        line("--- /mnt/su -c id -u ---");
        line(exec("/mnt/su", "-c", "id -u"));
        line("--- /mnt/su -c id ---");
        line(exec("/mnt/su", "-c", "id"));
        line("--- grep Cap /proc/self/status ---");
        line(exec("/mnt/su", "-c", "grep Cap /proc/self/status"));
        line("--- ls /data/data | wc -l ---");
        line(exec("/mnt/su", "-c", "ls /data/data | wc -l"));
        line("--- read wpa_supplicant.conf head ---");
        line(exec("/mnt/su", "-c", "head -1 /data/misc/wifi/wpa_supplicant.conf"));
    }

    private void line(String s) {
        log.append(s);
        if (!s.endsWith("\n")) log.append('\n');
    }

    private void dump(String s) {
        try {
            FileOutputStream f = new FileOutputStream(
                    new java.io.File(getFilesDir(), "r.txt"));
            f.write(s.getBytes("UTF-8"));
            f.close();
        } catch (Throwable t) {
            Log.e("SUTEST", "dump fail", t);
        }
    }

    /** 跑一条命令；用守护线程做 6 秒上限，避免 readLine 永久阻塞。 */
    private String exec(final String... argv) {
        final StringBuilder o = new StringBuilder();
        final Process[] ph = new Process[1];
        Thread w = new Thread(new Runnable() {
            public void run() {
                try {
                    Process p = Runtime.getRuntime().exec(argv);
                    ph[0] = p;
                    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    String l;
                    int n = 0;
                    while ((l = r.readLine()) != null) {
                        o.append(l).append('\n');
                        if (++n > 30) break;
                    }
                    p.waitFor();
                } catch (Throwable t) {
                    o.append("EXEC FAIL: ").append(t).append('\n');
                }
            }
        });
        w.setDaemon(true);
        w.start();
        try {
            w.join(6000);
        } catch (Throwable t) { }
        if (w.isAlive()) {
            o.append("(TIMEOUT 6s)\n");
            try { if (ph[0] != null) ph[0].destroy(); } catch (Throwable t) { }
        }
        return o.toString();
    }
}
