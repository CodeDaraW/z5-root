package android.content;

/* 编译期最小桩: 运行时由系统 framework 提供真实实现. */
public abstract class BroadcastReceiver {
    public abstract void onReceive(Context ctx, Intent it);
}
