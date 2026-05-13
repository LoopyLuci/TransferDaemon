package com.transferdaemon.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import androidx.core.app.NotificationCompat;

public class DaemonService extends Service {

    static {
        System.loadLibrary("transferd_mobile");
    }

    private static final String CHANNEL_ID = "transferdaemon_daemon";

    @Override
    public void onCreate() {
        super.onCreate();
        Notification notification = buildNotification();
        startForeground(1, notification);

        // Start the gRPC daemon on a background thread.
        // The socket path is unused; daemon listens on loopback TCP 127.0.0.1:50051.
        new Thread(() -> startDaemon("")).start();
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    /** Calls the C-ABI startDaemon exported by transferd_mobile. */
    private native void startDaemon(String socketPath);

    @SuppressWarnings("deprecation")
    private Notification buildNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "TransferDaemon Service", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Keeps the secure transfer daemon alive");
            NotificationManager mgr = getSystemService(NotificationManager.class);
            if (mgr != null) mgr.createNotificationChannel(channel);
            return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("TransferDaemon")
                .setContentText("Secure transfer daemon running")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .build();
        } else {
            // API 24/25: no notification channels; deprecated single-arg constructor is fine here.
            return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("TransferDaemon")
                .setContentText("Secure transfer daemon running")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();
        }
    }
}
