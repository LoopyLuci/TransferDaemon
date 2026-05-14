package com.transferdaemon.app;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;

/**
 * Transparent trampoline Activity that launches the system file picker and
 * delivers the chosen file path back to Rust via JNI.
 *
 * Usage from Rust: call FilePickerActivity.launch(activity).
 * Result: FilePickerActivity.deliverFilePath(path) is called from Java and
 *         forwarded to the Rust JNI symbol of the same name.
 */
public class FilePickerActivity extends Activity {

    private static final int REQUEST_CODE = 1001;

    /** Called by Rust JNI to start this activity from the NativeActivity context. */
    public static void launch(Activity parent) {
        Intent intent = new Intent(parent, FilePickerActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        parent.startActivity(intent);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Immediately launch the system file picker.
        Intent pick = new Intent(Intent.ACTION_GET_CONTENT);
        pick.setType("*/*");
        pick.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(Intent.createChooser(pick, "Select file"), REQUEST_CODE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_CODE && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                String path = resolveRealPath(uri);
                if (path != null) {
                    deliverFilePath(path);
                }
            }
        }
        finish(); // Close this transparent trampoline.
    }

    /**
     * Resolve a content:// Uri to an absolute filesystem path by copying to
     * the app's cache directory.  This is necessary because scoped storage
     * (Android 10+) does not allow direct /proc/self/fd paths for most URIs.
     */
    private String resolveRealPath(Uri uri) {
        try {
            // Try to get the display name.
            String displayName = "transfer_file";
            ContentResolver cr = getContentResolver();
            try (Cursor cursor = cr.query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (idx >= 0) displayName = cursor.getString(idx);
                }
            }

            // Copy to cache so Rust can open it with a plain path.
            java.io.File dest = new java.io.File(getCacheDir(), displayName);
            try (java.io.InputStream in = cr.openInputStream(uri);
                 java.io.FileOutputStream out = new java.io.FileOutputStream(dest)) {
                byte[] buf = new byte[65536];
                int n;
                while (in != null && (n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
            }
            return dest.getAbsolutePath();
        } catch (Exception e) {
            android.util.Log.e("FilePickerActivity", "resolveRealPath failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * JNI symbol implemented in Rust (`file_picker.rs`).
     * Stores the path in PENDING_PATH so the egui update loop can pick it up.
     */
    public static native void deliverFilePath(String path);
}
