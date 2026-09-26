package com.transferdaemon.app

import android.content.Context
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputMethodManager
import java.lang.ref.WeakReference

/**
 * Subclass of NativeActivity that fixes soft-keyboard visibility.
 *
 * NativeActivity's SurfaceView has inputType=TYPE_NULL so GBoard ignores
 * show_soft_input(). We add a 1×1 transparent view (mImeAnchor) that reports
 * inputType=TYPE_CLASS_TEXT. showKeyboard() focuses this view and calls
 * showSoftInput() on it, so GBoard calls its onCreateInputConnection() and shows.
 *
 * The anchor starts non-focusable to avoid focus-change ANRs during startup.
 * It becomes focusable only when showKeyboard() is explicitly called.
 */
class CustomNativeActivity : android.app.NativeActivity() {

    private var mImeAnchor: View? = null

    companion object {
        private var sInstance: WeakReference<CustomNativeActivity>? = null

        /** System bar insets in pixels — read by KeyboardHelper's polling thread. */
        @Volatile @JvmField var sTopInset: Int = 0
        @Volatile @JvmField var sBottomInset: Int = 0

        /** Called from Rust's keyboard polling thread via JNI to raise the soft keyboard. */
        @JvmStatic
        fun showKeyboard() {
            val activity = sInstance?.get() ?: return
            val anchor = activity.mImeAnchor ?: return
            activity.runOnUiThread {
                anchor.isFocusable = true
                anchor.isFocusableInTouchMode = true
                anchor.requestFocus()
                val imm = activity.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
                imm.showSoftInput(anchor, InputMethodManager.SHOW_FORCED)
            }
        }

        /** Called from Rust to hide the soft keyboard. */
        @JvmStatic
        fun hideKeyboard() {
            val activity = sInstance?.get() ?: return
            activity.runOnUiThread {
                val decor = activity.window.decorView
                val imm = activity.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
                imm.hideSoftInputFromWindow(decor.windowToken, 0)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sInstance = WeakReference(this)
        installInsetsListener()
        installImeAnchor()
        // Attach KeyboardHelper's hidden EditText to THIS activity's window.
        // Must be called here (not PermissionsActivity) so the EditText is in
        // the NativeActivity window that stays alive for the app's lifetime.
        KeyboardHelper.attach(this)
    }

    private fun installInsetsListener() {
        val decor = window.decorView
        decor.setOnApplyWindowInsetsListener { v, insets ->
            sTopInset = insets.systemWindowInsetTop
            sBottomInset = insets.systemWindowInsetBottom
            insets
        }
        // Request insets immediately in case the listener fires before the window is shown.
        decor.requestApplyInsets()
    }

    private fun installImeAnchor() {
        val anchor = object : View(this) {
            override fun onCheckIsTextEditor(): Boolean = true

            override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection {
                outAttrs.inputType = InputType.TYPE_CLASS_TEXT or
                        InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or
                        InputType.TYPE_TEXT_FLAG_MULTI_LINE
                outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI or
                        EditorInfo.IME_FLAG_NO_FULLSCREEN
                outAttrs.initialSelStart = 0
                outAttrs.initialSelEnd = 0
                return BaseInputConnection(this, true)
            }
        }
        anchor.isFocusable = true
        anchor.isFocusableInTouchMode = true
        anchor.alpha = 0f
        anchor.isClickable = false
        addContentView(anchor, ViewGroup.LayoutParams(1, 1))
        // Give focus after layout so the IMM always queries mImeAnchor
        // (not the SurfaceView with TYPE_NULL) when show_soft_input is called.
        anchor.post { anchor.requestFocus() }
        mImeAnchor = anchor
    }
}
