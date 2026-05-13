package com.transferdaemon.app;

import android.content.Intent;
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

        // Start the daemon service.
        Intent serviceIntent = new Intent(this, DaemonService.class);
        startForegroundService(serviceIntent);

        surfaceView = findViewById(R.id.surface_view);
        surfaceView.getHolder().addCallback(this);
    }

    // SurfaceHolder.Callback — UI starts when the surface is ready.
    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        // start_ui is a no-op stub on desktop builds; on a real Android build
        // it would drive an egui render loop via the native surface.
        startUi(holder.getSurface(), surfaceView.getWidth(), surfaceView.getHeight());
    }

    @Override public void surfaceChanged(SurfaceHolder h, int f, int w, int t) {}
    @Override public void surfaceDestroyed(SurfaceHolder holder) {}

    /** Calls the C-ABI start_ui exported by transferd_mobile. */
    private native void startUi(Object surface, int width, int height);
}
