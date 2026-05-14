package com.transferdaemon.app;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.media.Image;
import android.media.ImageReader;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;
import android.util.Size;

import java.nio.ByteBuffer;
import java.util.Collections;

/**
 * Camera2-based video capture helper.
 *
 * Call {@link #start()} to begin capture; Rust is notified via
 * {@link #deliverFrame(byte[], int, int)} on each YUV_420_888 frame.
 * Call {@link #stop()} to release all resources.
 *
 * All public methods are static so Rust can invoke them without holding a
 * Java object reference.
 */
public class CameraHelper {

    private static final String TAG = "CameraHelper";
    private static final int TARGET_WIDTH  = 640;
    private static final int TARGET_HEIGHT = 480;
    private static final int MAX_IMAGES    = 2;

    private static volatile Context      sContext;
    private static volatile HandlerThread sCameraThread;
    private static volatile Handler      sCameraHandler;
    private static volatile CameraDevice sCamera;
    private static volatile CameraCaptureSession sSession;
    private static volatile ImageReader  sImageReader;

    /** Called from NativeActivity after the app context is known. */
    public static void setContext(Context ctx) {
        sContext = ctx.getApplicationContext();
    }

    // ── Rust-callable static entry points ─────────────────────────────────────

    /** Begin camera capture.  No-op if already running. */
    public static void start() {
        if (sCamera != null) return;
        if (sContext == null) {
            Log.e(TAG, "start() called before setContext()");
            return;
        }
        sCameraThread = new HandlerThread("CameraHelper");
        sCameraThread.start();
        sCameraHandler = new Handler(sCameraThread.getLooper());
        sCameraHandler.post(CameraHelper::openCamera);
    }

    /** Stop capture and release all resources. */
    public static void stop() {
        if (sCameraHandler != null) {
            sCameraHandler.post(CameraHelper::releaseResources);
        }
    }

    // ── Internal implementation ───────────────────────────────────────────────

    @SuppressLint("MissingPermission")
    private static void openCamera() {
        try {
            CameraManager mgr = (CameraManager) sContext.getSystemService(Context.CAMERA_SERVICE);
            String cameraId = selectBackFacing(mgr);
            if (cameraId == null) {
                Log.e(TAG, "No back-facing camera found");
                return;
            }

            sImageReader = ImageReader.newInstance(
                    TARGET_WIDTH, TARGET_HEIGHT, ImageFormat.YUV_420_888, MAX_IMAGES);
            sImageReader.setOnImageAvailableListener(reader -> {
                try (Image image = reader.acquireLatestImage()) {
                    if (image != null) processImage(image);
                }
            }, sCameraHandler);

            mgr.openCamera(cameraId, new CameraDevice.StateCallback() {
                @Override
                public void onOpened(CameraDevice device) {
                    sCamera = device;
                    startCaptureSession();
                }
                @Override
                public void onDisconnected(CameraDevice device) {
                    device.close();
                    sCamera = null;
                }
                @Override
                public void onError(CameraDevice device, int error) {
                    Log.e(TAG, "Camera error: " + error);
                    device.close();
                    sCamera = null;
                }
            }, sCameraHandler);
        } catch (CameraAccessException e) {
            Log.e(TAG, "openCamera failed: " + e.getMessage());
        }
    }

    private static void startCaptureSession() {
        try {
            CaptureRequest.Builder builder =
                    sCamera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
            builder.addTarget(sImageReader.getSurface());

            sCamera.createCaptureSession(
                    Collections.singletonList(sImageReader.getSurface()),
                    new CameraCaptureSession.StateCallback() {
                        @Override
                        public void onConfigured(CameraCaptureSession session) {
                            sSession = session;
                            try {
                                session.setRepeatingRequest(
                                        builder.build(), null, sCameraHandler);
                            } catch (CameraAccessException e) {
                                Log.e(TAG, "setRepeatingRequest failed: " + e.getMessage());
                            }
                        }
                        @Override
                        public void onConfigureFailed(CameraCaptureSession session) {
                            Log.e(TAG, "Capture session configure failed");
                        }
                    },
                    sCameraHandler);
        } catch (CameraAccessException e) {
            Log.e(TAG, "createCaptureSession failed: " + e.getMessage());
        }
    }

    /**
     * Copy all three YUV planes into a single contiguous I420 byte array and
     * hand it to Rust.  Camera2 guarantees YUV_420_888 which is I420-compatible
     * when planes are read sequentially (Y, U, V).
     */
    private static void processImage(Image image) {
        int width  = image.getWidth();
        int height = image.getHeight();

        Image.Plane[] planes = image.getPlanes();
        ByteBuffer yBuf = planes[0].getBuffer();
        ByteBuffer uBuf = planes[1].getBuffer();
        ByteBuffer vBuf = planes[2].getBuffer();

        int ySize = yBuf.remaining();
        int uSize = uBuf.remaining();
        int vSize = vBuf.remaining();

        byte[] yuv = new byte[ySize + uSize + vSize];
        yBuf.get(yuv, 0,           ySize);
        uBuf.get(yuv, ySize,       uSize);
        vBuf.get(yuv, ySize + uSize, vSize);

        deliverFrame(yuv, width, height);
    }

    private static void releaseResources() {
        if (sSession != null) {
            try { sSession.stopRepeating(); } catch (Exception ignored) {}
            sSession.close();
            sSession = null;
        }
        if (sCamera != null) {
            sCamera.close();
            sCamera = null;
        }
        if (sImageReader != null) {
            sImageReader.close();
            sImageReader = null;
        }
        if (sCameraThread != null) {
            sCameraThread.quitSafely();
            sCameraThread = null;
            sCameraHandler = null;
        }
    }

    private static String selectBackFacing(CameraManager mgr) throws CameraAccessException {
        for (String id : mgr.getCameraIdList()) {
            CameraCharacteristics chars = mgr.getCameraCharacteristics(id);
            Integer facing = chars.get(CameraCharacteristics.LENS_FACING);
            if (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK) {
                return id;
            }
        }
        // Fall back to any available camera.
        String[] ids = mgr.getCameraIdList();
        return ids.length > 0 ? ids[0] : null;
    }

    // ── JNI symbol implemented in Rust (android_media.rs) ────────────────────

    /**
     * Called with a contiguous I420 buffer (Y plane, then U plane, then V plane).
     * Rust converts it to RGBA and pushes it to the active call session.
     */
    public static native void deliverFrame(byte[] yuv, int width, int height);
}
