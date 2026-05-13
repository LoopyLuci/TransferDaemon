package com.transferdaemon.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
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
        createNotificationChannel();
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("TransferDaemon")
            .setContentText("Secure transfer daemon running")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .build();
        startForeground(1, notification);

        // Start the gRPC daemon on a background thread.
        // The socket path is unused on this build (daemon listens on loopback TCP).
        new Thread(() -> startDaemon("")).start();
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    /** Calls the C-ABI start_daemon exported by transferd_mobile. */
    private native void startDaemon(String socketPath);

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
            CHANNEL_ID, "TransferDaemon Service", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Keeps the secure transfer daemon alive");
        NotificationManager mgr = getSystemService(NotificationManager.class);
        mgr.createNotificationChannel(channel);
    }
}
