package com.transferdaemon.app

import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import java.lang.ref.WeakReference

/**
 * Raises system notifications for incoming TransferDaemon messages.
 *
 * Called from Rust via JNI (`notifications.rs` → `postIncoming`) whenever the
 * daemon applies a new inbound 1:1 text message. Tapping the notification opens
 * the app (CustomNativeActivity) so the user can reply.
 */
object NotificationHelper {

    private const val CHANNEL_ID = "transferdaemon_messages"
    private const val TAG = "NotificationHelper"

    private var sContext: WeakReference<Context>? = null

    /** Called from PermissionsActivity before NativeActivity starts. */
    @JvmStatic
    fun setContext(ctx: Context) {
        sContext = WeakReference(ctx)
    }

    /** JNI entry point (Rust) — posts a notification for a new message. */
    @JvmStatic
    fun postIncoming(sender: String, text: String, contactId: String) {
        val ctx = sContext?.get() ?: return
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Messages",
                NotificationManager.IMPORTANCE_HIGH
            ).apply { description = "Incoming secure messages" }
            nm.createNotificationChannel(channel)
        }

        // Tapping opens the app.
        val open = Intent(ctx, CustomNativeActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra("open_contact", contactId)
        }
        val pending = PendingIntent.getActivity(
            ctx,
            contactId.hashCode() and 0xffff,
            open,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val preview = text.trim().take(160)
        val notification = NotificationCompat.Builder(ctx, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentTitle(sender)
            .setContentText(preview)
            .setStyle(NotificationCompat.BigTextStyle().bigText(preview))
            .setAutoCancel(true)
            .setContentIntent(pending)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()

        try {
            nm.notify(contactId.hashCode() and 0xffff, notification)
            Log.d(TAG, "posted notification for $sender")
        } catch (e: SecurityException) {
            // POST_NOTIFICATIONS not granted yet — silent, best-effort.
            Log.d(TAG, "notification permission not granted: ${e.message}")
        }
    }
}