package plus.meow.kqt

import android.app.NativeActivity
import android.content.Intent
import android.os.Bundle

class MainActivity : NativeActivity() {

    companion object {
        init {
            System.loadLibrary("kqt_android")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        notifyOnNewIntent()
    }

    private external fun notifyOnNewIntent()
}
