package com.transferdaemon.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat

/**
 * Foreground keep-alive service. Raising the process to FOREGROUND_SERVICE
 * (dataSync) exempts the app from Fire OS app-freeze / deep Doze, so the
 * daemon's WebSocket keeps sending frames and its relay registration stays
 * live. Also holds a PARTIAL_WAKE_LOCK while running.
 *
 * The daemon itself is started by the Rust `android_main` (spawn_with_config);
 * this service only keeps the process alive — it does NOT start a second one.
 */
class DaemonService : Service() {

    private var wakeLock: PowerManager.WakeLock? = null

    companion object {
        private const val CHANNEL_ID = "transferdaemon_daemon"
    }

    override fun onCreate() {
        super.onCreate()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(1, notification)
        }
        acquireWakeLock()
    }

    override fun onBind(intent: Intent): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onDestroy() {
        releaseWakeLock()
        super.onDestroy()
    }

    /** Keep the CPU + network stack active so the daemon threads keep running. */
    private fun acquireWakeLock() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "transferdaemon:daemon")
        wakeLock?.acquire()
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    @Suppress("DEPRECATION")
    private fun buildNotification(): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "TransferDaemon Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Keeps the secure transfer daemon alive" }
            val mgr = getSystemService(NotificationManager::class.java)
            mgr?.createNotificationChannel(channel)
            NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("TransferDaemon")
                .setContentText("Secure transfer daemon running")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .build()
        } else {
            NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("TransferDaemon")
                .setContentText("Secure transfer daemon running")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build()
        }
    }
}