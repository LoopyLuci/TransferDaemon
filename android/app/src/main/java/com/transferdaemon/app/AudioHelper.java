package com.transferdaemon.app;

import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.util.Log;

/**
 * Microphone capture helper using {@link AudioRecord}.
 *
 * Captures PCM 16-bit mono at 48 kHz in a background thread.  Each buffer is
 * delivered to Rust via {@link #deliverAudio(byte[])}. Rust converts the i16 LE
 * bytes to f32 samples and dispatches them to the active call session.
 *
 * All public methods are static so Rust can invoke them without a Java object.
 */
public class AudioHelper {

    private static final String TAG         = "AudioHelper";
    private static final int    SAMPLE_RATE = 48_000;
    // 10 ms per callback → 480 samples → 960 bytes (i16 = 2 bytes per sample)
    private static final int    FRAME_BYTES = 480 * 2;

    private static volatile AudioRecord sRecord;
    private static volatile Thread      sCaptureThread;
    private static volatile boolean     sRunning;

    // ── Rust-callable static entry points ─────────────────────────────────────

    /** Begin audio capture.  No-op if already running. */
    public static void start() {
        if (sRecord != null) return;

        int minBuf = AudioRecord.getMinBufferSize(
                SAMPLE_RATE,
                AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT);
        int bufSize = Math.max(minBuf, FRAME_BYTES * 4);

        sRecord = new AudioRecord(
                MediaRecorder.AudioSource.MIC,
                SAMPLE_RATE,
                AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT,
                bufSize);

        if (sRecord.getState() != AudioRecord.STATE_INITIALIZED) {
            Log.e(TAG, "AudioRecord failed to initialize");
            sRecord = null;
            return;
        }

        sRunning = true;
        sRecord.startRecording();

        sCaptureThread = new Thread(AudioHelper::captureLoop, "AudioHelper");
        sCaptureThread.setDaemon(true);
        sCaptureThread.start();
    }

    /** Stop capture and release AudioRecord. */
    public static void stop() {
        sRunning = false;
        AudioRecord rec = sRecord;
        sRecord = null;
        if (rec != null) {
            try { rec.stop(); } catch (Exception ignored) {}
            rec.release();
        }
        Thread t = sCaptureThread;
        sCaptureThread = null;
        if (t != null) {
            t.interrupt();
        }
    }

    // ── Capture loop ──────────────────────────────────────────────────────────

    private static void captureLoop() {
        byte[] buf = new byte[FRAME_BYTES];
        while (sRunning) {
            AudioRecord rec = sRecord;
            if (rec == null) break;

            int read = rec.read(buf, 0, buf.length);
            if (read > 0) {
                byte[] frame = new byte[read];
                System.arraycopy(buf, 0, frame, 0, read);
                deliverAudio(frame);
            } else if (read < 0) {
                Log.e(TAG, "AudioRecord.read error: " + read);
                break;
            }
        }
    }

    // ── JNI symbol implemented in Rust (android_media.rs) ────────────────────

    /**
     * Called with raw PCM 16-bit LE mono bytes at 48 kHz.
     * Rust chops them into 480-sample chunks (10 ms each) and queues them.
     */
    public static native void deliverAudio(byte[] pcmBytes);
}
