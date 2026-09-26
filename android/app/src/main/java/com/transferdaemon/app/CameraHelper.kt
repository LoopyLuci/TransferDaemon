package com.transferdaemon.app

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.ImageFormat
import android.hardware.camera2.CameraAccessException
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.Image
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.util.Log

/**
 * Camera2-based video capture helper.
 *
 * Call [start] to begin capture; Rust is notified via [deliverFrame] on each YUV_420_888 frame.
 * Call [stop] to release all resources.
 *
 * All public methods are annotated @JvmStatic so Rust can invoke them via
 * GetStaticMethodID without holding a Java object reference.
 */
object CameraHelper {

    private const val TAG           = "CameraHelper"
    private const val TARGET_WIDTH  = 640
    private const val TARGET_HEIGHT = 480
    private const val MAX_IMAGES    = 2

    @Volatile private var sContext: Context? = null
    @Volatile private var sCameraThread: HandlerThread? = null
    @Volatile private var sCameraHandler: Handler? = null
    @Volatile private var sCamera: CameraDevice? = null
    @Volatile private var sSession: CameraCaptureSession? = null
    @Volatile private var sImageReader: ImageReader? = null

    /** Called from NativeActivity after the app context is known. */
    @JvmStatic
    fun setContext(ctx: Context) {
        sContext = ctx.applicationContext
    }

    /**
     * Returns the logical display density factor.
     * Kept for possible future use; Rust queries density directly via ANativeActivity.
     */
    @JvmStatic
    fun getDisplayDensity(): Float {
        val ctx = sContext ?: return 1.0f
        val dpi = ctx.resources.displayMetrics.densityDpi
        return if (dpi > 0) dpi / 160.0f else 1.0f
    }

    /** Begin camera capture. No-op if already running. */
    @JvmStatic
    fun start() {
        if (sCamera != null) return
        val ctx = sContext ?: run {
            Log.e(TAG, "start() called before setContext()")
            return
        }
        val thread = HandlerThread("CameraHelper").also {
            it.start()
            sCameraThread = it
        }
        sCameraHandler = Handler(thread.looper)
        sCameraHandler!!.post { openCamera(ctx) }
    }

    /** Stop capture and release all resources. */
    @JvmStatic
    fun stop() {
        sCameraHandler?.post { releaseResources() }
    }

    // ── Internal implementation ───────────────────────────────────────────────

    @SuppressLint("MissingPermission")
    private fun openCamera(ctx: Context) {
        try {
            val mgr = ctx.getSystemService(Context.CAMERA_SERVICE) as CameraManager
            val cameraId = selectBackFacing(mgr) ?: run {
                Log.e(TAG, "No back-facing camera found")
                return
            }

            sImageReader = ImageReader.newInstance(
                TARGET_WIDTH, TARGET_HEIGHT, ImageFormat.YUV_420_888, MAX_IMAGES
            ).also { reader ->
                reader.setOnImageAvailableListener({ r ->
                    r.acquireLatestImage()?.use { processImage(it) }
                }, sCameraHandler)
            }

            mgr.openCamera(cameraId, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    sCamera = device
                    startCaptureSession()
                }
                override fun onDisconnected(device: CameraDevice) {
                    device.close()
                    sCamera = null
                }
                override fun onError(device: CameraDevice, error: Int) {
                    Log.e(TAG, "Camera error: $error")
                    device.close()
                    sCamera = null
                }
            }, sCameraHandler)
        } catch (e: CameraAccessException) {
            Log.e(TAG, "openCamera failed: ${e.message}")
        }
    }

    private fun startCaptureSession() {
        val camera = sCamera ?: return
        val reader = sImageReader ?: return
        try {
            val builder = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                addTarget(reader.surface)
            }
            camera.createCaptureSession(
                listOf(reader.surface),
                object : CameraCaptureSession.StateCallback() {
                    override fun onConfigured(session: CameraCaptureSession) {
                        sSession = session
                        try {
                            session.setRepeatingRequest(builder.build(), null, sCameraHandler)
                        } catch (e: CameraAccessException) {
                            Log.e(TAG, "setRepeatingRequest failed: ${e.message}")
                        }
                    }
                    override fun onConfigureFailed(session: CameraCaptureSession) {
                        Log.e(TAG, "Capture session configure failed")
                    }
                },
                sCameraHandler
            )
        } catch (e: CameraAccessException) {
            Log.e(TAG, "createCaptureSession failed: ${e.message}")
        }
    }

    /**
     * Copy all three YUV planes into a single contiguous I420 byte array and
     * hand it to Rust. Camera2 guarantees YUV_420_888 which is I420-compatible
     * when planes are read sequentially (Y, U, V).
     */
    private fun processImage(image: Image) {
        val width  = image.width
        val height = image.height
        val planes = image.planes
        val yBuf = planes[0].buffer
        val uBuf = planes[1].buffer
        val vBuf = planes[2].buffer

        val ySize = yBuf.remaining()
        val uSize = uBuf.remaining()
        val vSize = vBuf.remaining()

        val yuv = ByteArray(ySize + uSize + vSize)
        yBuf.get(yuv, 0,           ySize)
        uBuf.get(yuv, ySize,       uSize)
        vBuf.get(yuv, ySize + uSize, vSize)

        deliverFrame(yuv, width, height)
    }

    private fun releaseResources() {
        sSession?.let {
            try { it.stopRepeating() } catch (_: Exception) {}
            it.close()
            sSession = null
        }
        sCamera?.let { it.close(); sCamera = null }
        sImageReader?.let { it.close(); sImageReader = null }
        sCameraThread?.let {
            it.quitSafely()
            sCameraThread = null
            sCameraHandler = null
        }
    }

    private fun selectBackFacing(mgr: CameraManager): String? {
        for (id in mgr.cameraIdList) {
            val chars = mgr.getCameraCharacteristics(id)
            val facing = chars.get(CameraCharacteristics.LENS_FACING)
            if (facing == CameraCharacteristics.LENS_FACING_BACK) return id
        }
        return mgr.cameraIdList.firstOrNull()
    }

    // ── JNI symbol implemented in Rust (android_media.rs) ────────────────────

    /**
     * Called with a contiguous I420 buffer (Y plane, then U plane, then V plane).
     * Rust converts it to RGBA and pushes it to the active call session.
     */
    @JvmStatic external fun deliverFrame(yuv: ByteArray, width: Int, height: Int)
}
