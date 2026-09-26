package com.transferdaemon.app

import android.app.Activity
import android.content.ContentResolver
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.lang.ref.WeakReference

/**
 * Transparent trampoline Activity that launches the system file picker and
 * delivers the chosen file path back to Rust via JNI.
 *
 * Usage from Rust: call FilePickerActivity.launch().
 * Result: [deliverFilePath] is called from Java and forwarded to the Rust JNI symbol.
 */
class FilePickerActivity : Activity() {

    companion object {
        private const val REQUEST_CODE = 1001
        private const val TAG = "FilePickerActivity"

        private var sContext: WeakReference<Activity>? = null

        /** Called from PermissionsActivity before NativeActivity starts. */
        @JvmStatic
        fun setContext(ctx: Activity) {
            sContext = WeakReference(ctx)
        }

        /** Called by Rust JNI — no Activity argument needed; uses stored context. */
        @JvmStatic
        fun launch() {
            val parent = sContext?.get() ?: return
            val intent = Intent(parent, FilePickerActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            parent.startActivity(intent)
        }

        /** Legacy overload kept for source compatibility. */
        @JvmStatic
        fun launch(parent: Activity) {
            sContext = WeakReference(parent)
            launch()
        }

        /**
         * JNI symbol implemented in Rust (file_picker.rs).
         * Stores the path in PENDING_PATH so the egui update loop can pick it up.
         */
        @JvmStatic external fun deliverFilePath(path: String)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // ACTION_OPEN_DOCUMENT (Storage Access Framework) supports persistable
        // URI permissions, so a chosen document stays readable across app
        // restarts — which keeps long, resumed transfers working.
        val pick = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        @Suppress("DEPRECATION")
        startActivityForResult(Intent.createChooser(pick, "Select file"), REQUEST_CODE)
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_CODE && resultCode == RESULT_OK && data != null) {
            val uri = data.data
            if (uri != null) {
                // Persist read access so resumed transfers can reopen the doc.
                try {
                    contentResolver.takePersistableUriPermission(
                        uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION
                    )
                } catch (_: Exception) {
                    // Best-effort: some providers (e.g. Downloads) refuse persistence.
                }
                val path = resolveRealPath(uri)
                if (path != null) deliverFilePath(path)
            }
        }
        finish() // Close this transparent trampoline.
    }

    /**
     * Resolve a content:// Uri to an absolute filesystem path by copying to
     * the app's cache directory. This is necessary because scoped storage
     * (Android 10+) does not allow direct /proc/self/fd paths for most URIs.
     */
    private fun resolveRealPath(uri: Uri): String? {
        return try {
            var displayName = "transfer_file"
            val cr: ContentResolver = contentResolver
            cr.query(uri, null, null, null, null)?.use { cursor: Cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) displayName = cursor.getString(idx)
                }
            }

            val dest = File(cacheDir, displayName)
            cr.openInputStream(uri)?.use { input ->
                FileOutputStream(dest).use { output ->
                    val buf = ByteArray(65536)
                    var n: Int
                    while (input.read(buf).also { n = it } != -1) {
                        output.write(buf, 0, n)
                    }
                }
            }
            dest.absolutePath
        } catch (e: Exception) {
            Log.e(TAG, "resolveRealPath failed: ${e.message}")
            null
        }
    }
}
