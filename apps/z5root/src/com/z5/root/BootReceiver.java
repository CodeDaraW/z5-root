package com.z5.root;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * 开机自动续跑。
 *
 * 背景：exploit 建 UAF 时，`MCAST_LEAVE_GROUP` 那一步有 ~40% 概率触发内核 panic，
 * 而那时 `panic_on_oops` 还是 1（PDEC 走不到），所以手机必然黑屏重启。
 * 这一步是在"拿到内核读写原语之前"完成的，没法提前关掉 panic_on_oops。
 *
 * 于是：用户点一次「开始 ROOT」= 授权。只要没成功，就在下次开机时自动再跑一次，
 * 最多 3 次。成功后立刻删掉 pending.txt，之后开机一律不动（"不触发就不跑"）。
 *
 * 这个接收器本身不做任何危险操作，只是拉起 MainActivity 继续那一次用户授权的尝试。
 */
public class BootReceiver extends BroadcastReceiver {

    static final int MAX_BOOT_TRY = 3;

    @Override
    public void onReceive(Context ctx, Intent it) {
        try {
            String dir = ctx.getFilesDir().getAbsolutePath();
            File f = new File(dir + "/pending.txt");
            if (!f.exists()) {
                Log.i("Z5", "boot: pending 不存在, 不自动跑");
                return;
            }
            int n = 0;
            try {
                String s = readAll(f).trim();
                if (s.length() > 0) n = Integer.parseInt(s);
            } catch (Throwable t) { }
            if (n < 1) {
                f.delete();
                Log.i("Z5", "boot: pending 无效, 清掉");
                return;
            }
            if (n >= MAX_BOOT_TRY) {
                f.delete();
                Log.i("Z5", "boot: 已经试了 " + n + " 次, 放弃自动续跑");
                return;
            }
            writeAll(f, String.valueOf(n + 1));
            Log.i("Z5", "boot: 第 " + (n + 1) + " 次自动续跑");

            Intent a = new Intent(ctx, MainActivity.class);
            a.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            a.putExtra("auto", true);
            ctx.startActivity(a);
        } catch (Throwable t) {
            Log.e("Z5", "boot receiver fail", t);
        }
    }

    private static String readAll(File f) {
        try {
            FileInputStream in = new FileInputStream(f);
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] b = new byte[512];
            int n;
            while ((n = in.read(b)) > 0) bo.write(b, 0, n);
            in.close();
            return new String(bo.toByteArray(), "UTF-8");
        } catch (Throwable t) {
            return "";
        }
    }

    private static void writeAll(File f, String s) {
        try {
            FileOutputStream o = new FileOutputStream(f);
            o.write(s.getBytes("UTF-8"));
            o.close();
        } catch (Throwable t) { }
    }
}
