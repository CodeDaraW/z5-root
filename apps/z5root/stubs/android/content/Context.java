package android.content;

/* 仅用于编译期解析的最小桩: 这里的方法体永远不会被真正执行,
   dex 中通过 --lib 排除, 运行时由系统的 framework 提供实现. */
public class Context {
    public java.io.File getFilesDir() { return null; }
    public android.content.res.AssetManager getAssets() { return null; }
    public String getPackageName() { return null; }
    public Context getApplicationContext() { return null; }
    public void startActivity(android.content.Intent i) { }
}
