package com.transferdaemon.app

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
import java.io.File
import java.io.FileOutputStream

/**
 * Receives content shared from other apps (ACTION_SEND) and hands it to the
 * Rust app. Files are copied to the app cache so the daemon can read a real
 * path (scoped storage forbids direct /proc/self/fd access on Android 10+).
 */
object ShareBridge {

    private const val TAG = "ShareBridge"

    /** JNI symbol implemented in Rust (share_bridge.rs). */
    @JvmStatic external fun deliverSharedFile(path: String, mime: String)
    /** JNI symbol implemented in Rust (share_bridge.rs). */
    @JvmStatic external fun deliverSharedText(text: String)

    /**
     * Called from PermissionsActivity when the app is launched via a share
     * intent. Copies the first stream to cache and forwards to Rust.
     */
    @JvmStatic
    fun handleShare(ctx: Context, intent: Intent) {
        val action = intent.action ?: return
        Log.d(TAG, "handleShare: action=$action text=${intent.getStringExtra(Intent.EXTRA_TEXT)}")
        if (action == Intent.ACTION_SEND) {
            val stream = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
            if (stream != null) {
                val path = resolveToCache(ctx, stream)
                Log.d(TAG, "handleShare: resolved stream to $path")
                if (path != null) {
                    val mime = intent.type ?: ""
                    deliverSharedFile(path, mime)
                }
                return
            }
            val text = intent.getStringExtra(Intent.EXTRA_TEXT)
            if (!text.isNullOrBlank()) {
                Log.d(TAG, "handleShare: delivering text")
                deliverSharedText(text.trim())
            }
        } else if (action == Intent.ACTION_SEND_MULTIPLE) {
            val streams = intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)
            val first = streams?.firstOrNull()
            if (first != null) {
                val path = resolveToCache(ctx, first)
                if (path != null) deliverSharedFile(path, intent.type ?: "")
            }
        }
    }

    /** Copy a content:// Uri into the app cache and return the real path. */
    private fun resolveToCache(ctx: Context, uri: Uri): String? {
        return try {
            var displayName = "shared_file"
            val cr: ContentResolver = ctx.contentResolver
            cr.query(uri, null, null, null, null)?.use { cursor: Cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) displayName = cursor.getString(idx)
                }
            }

            val dest = File(ctx.cacheDir, displayName)
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
            Log.e(TAG, "resolveToCache failed: ${e.message}")
            null
        }
    }
}