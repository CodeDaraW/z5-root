package android.app;

public class Activity extends android.content.Context {
    protected void onCreate(android.os.Bundle b) { }
    protected void onDestroy() { }
    public void setContentView(android.view.View v) { }
    public void runOnUiThread(Runnable r) { }
    public android.content.res.AssetManager getAssets() { return null; }
    public java.io.File getFilesDir() { return null; }
    public java.io.File getExternalFilesDir(String t) { return null; }
    public android.content.Intent getIntent() { return null; }
    public void startActivity(android.content.Intent i) { }
    public void finish() { }
    public void finishAndRemoveTask() { }
}
