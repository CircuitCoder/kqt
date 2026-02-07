package plus.meow.kqt.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.KeyGenerator

/**
 * Detects Android Keystore hardware capabilities.
 */
class KeystoreCapabilities(private val context: Context) {

    /**
     * Check if the device supports hardware-backed keystore (TEE).
     */
    fun supportsHardwareBackedKeystore(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return context.packageManager.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE)
        }
        // For older versions, assume hardware-backed if device has secure lock screen
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as? android.app.KeyguardManager
        return keyguardManager?.isDeviceSecure == true
    }

    /**
     * Check if the device supports StrongBox.
     * StrongBox is a hardware-isolated secure element (Android 9+).
     */
    fun supportsStrongBox(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return false
        }

        // Try to create a test key with StrongBox
        return try {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )

            val spec = KeyGenParameterSpec.Builder(
                "test_strongbox_capability",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(true)
                .build()

            keyGenerator.init(spec)
            keyGenerator.generateKey()

            // Clean up test key
            val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            keyStore.deleteEntry("test_strongbox_capability")

            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check if biometric authentication is available.
     */
    fun supportsBiometric(): Boolean {
        return context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) ||
                (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                        context.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE))
    }

    /**
     * Get a summary of all capabilities.
     */
    data class Capabilities(
        val hardwareBackedKeystore: Boolean,
        val strongBox: Boolean,
        val biometric: Boolean
    )

    fun getCapabilities(): Capabilities {
        return Capabilities(
            hardwareBackedKeystore = supportsHardwareBackedKeystore(),
            strongBox = supportsStrongBox(),
            biometric = supportsBiometric()
        )
    }
}


