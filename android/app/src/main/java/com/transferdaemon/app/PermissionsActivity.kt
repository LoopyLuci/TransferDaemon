package com.transferdaemon.app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.TextView

/**
 * Requests CAMERA and RECORD_AUDIO at runtime (required since Android 6.0),
 * then hands off to the real NativeActivity.
 *
 * This activity is the LAUNCHER; NativeActivity is no longer exported as
 * the launcher so the system always goes through this gate first.
 */
class PermissionsActivity : Activity() {

    companion object {
        private const val REQ = 1001
        private val REQUIRED = arrayOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
        )

        init {
            // Load eagerly so the share bridge + notification JNI symbols exist
            // before onCreate() runs (share intents deliver before NativeActivity).
            System.loadLibrary("transferd_mobile")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // If the app was opened via a share intent (another app sharing content
        // to TransferDaemon), capture it BEFORE the permission gate so the
        // payload reaches Rust even while the request dialog is up.
        ShareBridge.handleShare(this, intent)

        // Runtime permissions were introduced in API 23 (Android 6.0).
        // On API 22 and below, all manifest permissions are granted at install time.
        if (Build.VERSION.SDK_INT < 23) {
            launch()
            return
        }

        // On API 33+, POST_NOTIFICATIONS must be granted for message alerts.
        // Included here so notifications work; the app degrades gracefully if
        // the user denies (the daemon still receives + stores messages).
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ)
        }

        if (allGranted()) {
            launch()
        } else {
            // Show a minimal status while waiting.
            val tv = TextView(this).apply {
                text = "TransferDaemon needs camera and microphone permission."
                setPadding(48, 48, 48, 48)
            }
            setContentView(tv)
            requestPermissions(REQUIRED, REQ)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<String>,
        results: IntArray
    ) {
        // We proceed regardless — the app degrades gracefully without camera/mic.
        launch()
    }

    private fun allGranted(): Boolean {
        if (Build.VERSION.SDK_INT < 23) return true
        return REQUIRED.all { checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }
    }

    private fun launch() {
        // Pass the application context to camera/audio helpers before NativeActivity
        // initialises Rust so the static helpers are ready when start() is called.
        CameraHelper.setContext(this)
        FilePickerActivity.setContext(this)
        NotificationHelper.setContext(applicationContext)
        // KeyboardHelper is attached from Rust after NativeActivity starts —
        // calling attach() here would bind to PermissionsActivity's window which finishes immediately.

        val intent = Intent(this, CustomNativeActivity::class.java).apply {
            // Forward any extras the launcher may have attached (e.g. deep-link URIs).
            getIntent().extras?.let { putExtras(it) }
            addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION)
        }
        startActivity(intent)
        finish()
    }
}
