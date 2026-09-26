package com.transferdaemon.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

class DaemonService : Service() {

    companion object {
        init {
            System.loadLibrary("transferd_mobile")
        }

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

        // Start the gRPC daemon on a background thread.
        // The socket path is unused; daemon listens on loopback TCP 127.0.0.1:50051.
        Thread { startDaemon("") }.start()
    }

    override fun onBind(intent: Intent): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    /** Calls the C-ABI startDaemon exported by transferd_mobile. */
    private external fun startDaemon(socketPath: String)

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
            // API 24/25: no notification channels; deprecated single-arg constructor is fine here.
            NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("TransferDaemon")
                .setContentText("Secure transfer daemon running")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build()
        }
    }
}
