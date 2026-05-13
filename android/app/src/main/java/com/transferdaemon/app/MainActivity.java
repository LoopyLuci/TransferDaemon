package com.transferdaemon.app;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity implements SurfaceHolder.Callback {

    static {
        System.loadLibrary("transferd_mobile");
    }

    private SurfaceView surfaceView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Start the daemon service. startForegroundService requires API 26+;
        // on older devices startService is sufficient (service calls startForeground itself).
        Intent serviceIntent = new Intent(this, DaemonService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }

        surfaceView = findViewById(R.id.surface_view);
        surfaceView.getHolder().addCallback(this);
    }

    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        startUi(holder.getSurface(), surfaceView.getWidth(), surfaceView.getHeight());
    }

    @Override public void surfaceChanged(SurfaceHolder h, int f, int w, int t) {}
    @Override public void surfaceDestroyed(SurfaceHolder holder) {}

    /** Calls the JNI startUi exported by transferd_mobile. */
    private native void startUi(Object surface, int width, int height);
}
