package com.transferdaemon.app

import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.util.Log

/**
 * Microphone capture helper using [AudioRecord].
 *
 * Captures PCM 16-bit mono at 48 kHz in a background thread. Each buffer is
 * delivered to Rust via [deliverAudio]. Rust converts the i16 LE bytes to f32
 * samples and dispatches them to the active call session.
 *
 * All public methods are annotated @JvmStatic so Rust can invoke them via
 * GetStaticMethodID without holding a Java object reference.
 */
object AudioHelper {

    private const val TAG         = "AudioHelper"
    private const val SAMPLE_RATE = 48_000
    // 10 ms per callback → 480 samples → 960 bytes (i16 = 2 bytes per sample)
    private const val FRAME_BYTES = 480 * 2

    @Volatile private var sRecord: AudioRecord? = null
    @Volatile private var sCaptureThread: Thread? = null
    @Volatile private var sRunning: Boolean = false

    /** Begin audio capture. No-op if already running. */
    @JvmStatic
    fun start() {
        if (sRecord != null) return

        val minBuf = AudioRecord.getMinBufferSize(
            SAMPLE_RATE,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT
        )
        val bufSize = maxOf(minBuf, FRAME_BYTES * 4)

        val record = AudioRecord(
            MediaRecorder.AudioSource.MIC,
            SAMPLE_RATE,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            bufSize
        )

        if (record.state != AudioRecord.STATE_INITIALIZED) {
            Log.e(TAG, "AudioRecord failed to initialize")
            return
        }

        sRecord = record
        sRunning = true
        record.startRecording()

        sCaptureThread = Thread(::captureLoop, "AudioHelper").also {
            it.isDaemon = true
            it.start()
        }
    }

    /** Stop capture and release AudioRecord. */
    @JvmStatic
    fun stop() {
        sRunning = false
        sRecord?.let { rec ->
            sRecord = null
            try { rec.stop() } catch (_: Exception) {}
            rec.release()
        }
        sCaptureThread?.let { t ->
            sCaptureThread = null
            t.interrupt()
        }
    }

    // ── Capture loop ──────────────────────────────────────────────────────────

    private fun captureLoop() {
        val buf = ByteArray(FRAME_BYTES)
        while (sRunning) {
            val rec = sRecord ?: break
            val read = rec.read(buf, 0, buf.size)
            when {
                read > 0 -> deliverAudio(buf.copyOf(read))
                read < 0 -> {
                    Log.e(TAG, "AudioRecord.read error: $read")
                    break
                }
            }
        }
    }

    // ── JNI symbol implemented in Rust (android_media.rs) ────────────────────

    /**
     * Called with raw PCM 16-bit LE mono bytes at 48 kHz.
     * Rust chops them into 480-sample chunks (10 ms each) and queues them.
     */
    @JvmStatic external fun deliverAudio(pcmBytes: ByteArray)
}
