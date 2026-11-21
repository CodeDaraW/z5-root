package android.content;

/* 编译期最小桩: 运行时由系统 framework 提供真实实现,
   D8 通过 --lib 把它们当库处理, 不会进 dex. */
public class Intent {
    public static final int FLAG_ACTIVITY_NEW_TASK              = 0x10000000;
    public static final int FLAG_ACTIVITY_CLEAR_TOP             = 0x04000000;
    public static final int FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS  = 0x00800000;

    public Intent() { }
    public Intent(Context ctx, Class<?> cls) { }

    public Intent addFlags(int flags) { return this; }
    public int getFlags() { return 0; }
    public Intent putExtra(String k, boolean v) { return this; }
    public boolean getBooleanExtra(String k, boolean def) { return def; }
}
