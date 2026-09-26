package com.transferdaemon.app

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.text.InputType
import android.view.KeyEvent
import android.view.ViewGroup
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.FrameLayout
import java.lang.ref.WeakReference

/**
 * Manages a hidden 1x1 EditText that acts as the IME target for the NativeActivity window.
 *
 * Unlike a TextWatcher approach, we override onCreateInputConnection() and intercept text at
 * the IME protocol level. This prevents the "text repetition" bug that occurs when an IME
 * (GBoard, Samsung, SwiftKey, etc.) uses composing spans: after a TextWatcher-based sentinel
 * reset, the IME re-sends its accumulated composing text on the next keypress, duplicating
 * characters in egui.
 *
 * The custom InputConnection tracks the active composing string and only delivers the DELTA
 * to Rust - so every keyboard (letter-by-letter, swipe/gesture, autocorrect, hardware)
 * produces exactly one character event per physical key press.
 *
 * Keyboard show/hide is driven by Java polling Rust (shouldShowKeyboard / shouldHideKeyboard).
 */
object KeyboardHelper {

    init {
        try {
            System.loadLibrary("transferd_mobile")
        } catch (_: UnsatisfiedLinkError) {
            // Library already properly registered - no-op.
        }
    }

    @Volatile private var sActivity: WeakReference<Activity>? = null
    @Volatile private var sEditText: EditText? = null

    /**
     * Called from CustomNativeActivity.onCreate() to bind the hidden EditText
     * to the NativeActivity window and start the keyboard polling thread.
     */
    @JvmStatic
    fun attach(activity: Activity) {
        sActivity = WeakReference(activity)
        activity.runOnUiThread {
            val et = object : EditText(activity) {
                override fun onCheckIsTextEditor(): Boolean = true

                override fun onCreateInputConnection(outAttrs: EditorInfo): BaseInputConnection {
                    outAttrs.inputType = InputType.TYPE_CLASS_TEXT or
                            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                    outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI or
                            EditorInfo.IME_FLAG_NO_FULLSCREEN
                    outAttrs.initialSelStart = 0
                    outAttrs.initialSelEnd = 0

                    return object : BaseInputConnection(this, false) {

                        private val mComposing = StringBuilder()

                        override fun commitText(text: CharSequence, newCursorPosition: Int): Boolean {
                            var str = text.toString()
                            val composing = mComposing.toString()
                            mComposing.setLength(0)
                            if (str.startsWith(composing)) {
                                str = str.substring(composing.length)
                            } else {
                                repeat(composing.length) { deliverBackspace() }
                            }
                            deliver(str)
                            return true
                        }

                        override fun setComposingText(text: CharSequence, newCursorPosition: Int): Boolean {
                            val newComposing = text.toString()
                            if (newComposing.startsWith(mComposing.toString())) {
                                deliver(newComposing.substring(mComposing.length))
                            } else {
                                repeat(mComposing.length) { deliverBackspace() }
                                deliver(newComposing)
                            }
                            mComposing.setLength(0)
                            mComposing.append(newComposing)
                            return true
                        }

                        override fun finishComposingText(): Boolean {
                            mComposing.setLength(0)
                            return true
                        }

                        override fun setComposingRegion(start: Int, end: Int): Boolean = true

                        override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean {
                            val trim = minOf(beforeLength, mComposing.length)
                            mComposing.setLength(mComposing.length - trim)
                            repeat(beforeLength) { deliverBackspace() }
                            notifyRepaint()
                            return true
                        }

                        override fun sendKeyEvent(event: KeyEvent): Boolean {
                            if (event.action == KeyEvent.ACTION_DOWN) {
                                when (event.keyCode) {
                                    KeyEvent.KEYCODE_DEL -> {
                                        if (mComposing.isNotEmpty())
                                            mComposing.setLength(mComposing.length - 1)
                                        deliverBackspace()
                                        notifyRepaint()
                                        return true
                                    }
                                    KeyEvent.KEYCODE_ENTER -> {
                                        deliverEnter()
                                        notifyRepaint()
                                        return true
                                    }
                                    else -> {
                                        val ch = event.unicodeChar
                                        if (ch != 0 && ch != '\r'.code) {
                                            deliverText(ch.toChar().toString())
                                            notifyRepaint()
                                            return true
                                        }
                                    }
                                }
                            }
                            return super.sendKeyEvent(event)
                        }

                        override fun getTextBeforeCursor(n: Int, flags: Int): CharSequence = ""
                        override fun getTextAfterCursor(n: Int, flags: Int): CharSequence = ""
                        override fun getSelectedText(flags: Int): CharSequence? = null
                        override fun getCursorCapsMode(reqModes: Int): Int = 0

                        private fun deliver(s: String) {
                            for (c in s) {
                                when (c) {
                                    '\n' -> deliverEnter()
                                    '\r' -> {}
                                    else -> deliverText(c.toString())
                                }
                            }
                            notifyRepaint()
                        }
                    }
                }
            }

            et.layoutParams = FrameLayout.LayoutParams(1, 1)
            et.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            et.imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI or EditorInfo.IME_FLAG_NO_FULLSCREEN
            et.visibility = android.view.View.VISIBLE
            et.alpha = 0f

            val container = FrameLayout(activity)
            container.addView(et)
            activity.addContentView(
                container,
                ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
            )
            sEditText = et
        }

        val poller = Thread {
            while (!Thread.currentThread().isInterrupted) {
                try { Thread.sleep(32) } catch (_: InterruptedException) { break }
                if (shouldShowKeyboard()) showKeyboard()
                else if (shouldHideKeyboard()) hideKeyboard()
                val clip = getClipboardText()
                if (clip != null) copyToClipboard(clip)
                deliverInsets(CustomNativeActivity.sTopInset, CustomNativeActivity.sBottomInset)
            }
        }
        poller.isDaemon = true
        poller.name = "td-kb-poller"
        poller.start()
    }

    @JvmStatic
    fun showKeyboard() {
        val activity = sActivity?.get() ?: return
        val et = sEditText ?: return
        activity.runOnUiThread {
            et.requestFocus()
            val imm = activity.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
            imm.showSoftInput(et, InputMethodManager.SHOW_FORCED)
        }
    }

    @JvmStatic
    fun hideKeyboard() {
        val activity = sActivity?.get() ?: return
        val et = sEditText ?: return
        activity.runOnUiThread {
            val imm = activity.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
            imm.hideSoftInputFromWindow(et.windowToken, 0)
        }
    }

    private fun copyToClipboard(text: String) {
        val activity = sActivity?.get() ?: return
        activity.runOnUiThread {
            val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("TransferDaemon", text))
        }
    }

    @JvmStatic external fun shouldShowKeyboard(): Boolean
    @JvmStatic external fun shouldHideKeyboard(): Boolean
    @JvmStatic external fun getClipboardText(): String?
    @JvmStatic external fun deliverText(text: String)
    @JvmStatic external fun deliverBackspace()
    @JvmStatic external fun deliverEnter()
    @JvmStatic external fun deliverInsets(topPx: Int, bottomPx: Int)
    @JvmStatic external fun notifyRepaint()
}