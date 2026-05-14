package com.transferdaemon.app;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.widget.TextView;

/**
 * Requests CAMERA and RECORD_AUDIO at runtime (required since Android 6.0),
 * then hands off to the real NativeActivity.
 *
 * This activity is the LAUNCHER; NativeActivity is no longer exported as
 * the launcher so the system always goes through this gate first.
 */
public class PermissionsActivity extends Activity {

    private static final int REQ = 1001;

    private static final String[] REQUIRED = {
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (allGranted()) {
            launch();
        } else {
            // Show a minimal status while waiting.
            TextView tv = new TextView(this);
            tv.setText("TransferDaemon needs camera and microphone permission.");
            tv.setPadding(48, 48, 48, 48);
            setContentView(tv);
            requestPermissions(REQUIRED, REQ);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        // We proceed regardless — the app degrades gracefully without camera/mic.
        launch();
    }

    private boolean allGranted() {
        for (String perm : REQUIRED) {
            if (checkSelfPermission(perm) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    private void launch() {
        // Pass the application context to camera/audio helpers before NativeActivity
        // initialises Rust so the static helpers are ready when start() is called.
        CameraHelper.setContext(this);

        Intent intent = new Intent(this, android.app.NativeActivity.class);
        // Forward any extras the launcher may have attached (e.g. deep-link URIs).
        if (getIntent().getExtras() != null) {
            intent.putExtras(getIntent().getExtras());
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION);
        startActivity(intent);
        finish();
    }
}
