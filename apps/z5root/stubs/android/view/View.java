package android.view;

public class View {
    public View(android.content.Context c) { }
    public interface OnClickListener {
        void onClick(View v);
    }
    public void setOnClickListener(OnClickListener l) { }
    public void setEnabled(boolean e) { }
    public void setPadding(int l, int t, int r, int b) { }
}
