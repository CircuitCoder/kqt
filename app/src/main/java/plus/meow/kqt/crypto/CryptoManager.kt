package plus.meow.kqt.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import plus.meow.kqt.utils.Result
import javax.crypto.SecretKeyFactory

/**
 * Manages encryption/decryption using Android Keystore.
 *
 * Uses a single master AES-256-GCM key stored in the best available keystore backend
 * (StrongBox if available, otherwise TEE).
 */
class CryptoManager(
    private val activity: FragmentActivity,
    private val provisioningManager: KeyProvisioningManager
) {

    private val biometricAuthManager: BiometricAuthManager by lazy {
        BiometricAuthManager(activity)
    }

    companion object {
        private const val MASTER_KEY_ALIAS = "vpn_master_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128 // bits

        /**
         * Encrypted data container.
         */
        data class EncryptedData(
            val iv: ByteArray,
            val ciphertext: ByteArray
        ) {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (javaClass != other?.javaClass) return false

                other as EncryptedData

                if (!iv.contentEquals(other.iv)) return false
                if (!ciphertext.contentEquals(other.ciphertext)) return false

                return true
            }

            override fun hashCode(): Int {
                var result = iv.contentHashCode()
                result = 31 * result + ciphertext.contentHashCode()
                return result
            }
        }

        private fun doesKeyRequireAuth(key: SecretKey): Boolean {
            try {
                val factory = javax.crypto.SecretKeyFactory.getInstance(
                    key.algorithm,
                    ANDROID_KEYSTORE
                )
                val keyInfo = factory.getKeySpec(
                    key,
                    android.security.keystore.KeyInfo::class.java
                ) as android.security.keystore.KeyInfo
                return keyInfo.isUserAuthenticationRequired
            } catch (e: Exception) {
                return false;
            }
        }

        private fun isUserNotAuthenticated(e: Throwable): Boolean {
            if (e is UserNotAuthenticatedException) return true;
            val cause = e.cause
            if (cause != null) return isUserNotAuthenticated(cause);
            return false;
        }
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    /**
     * Get the master encryption key and perform authentication if required.
     *
     * @return SecretKey if successful, null if authentication failed
     * @throws IllegalStateException if key doesn't exist (not provisioned)
     */
    private fun getMasterKey(): SecretKey? {
        if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) {
            return null
        }

        val masterKey = keyStore.getKey(MASTER_KEY_ALIAS, null) as SecretKey
        return masterKey
    }

    /**
     * Create the master encryption key in Android Keystore.
     * Attempts to use StrongBox if available, falls back to TEE.
     *
     * @param securityTier The security tier configuration for authentication requirements
     */
    private fun createMasterKey(securityTier: SecurityTier): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val builder = KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)

        // Configure authentication based on security tier
        if (securityTier.requiresAuthentication()) {
            builder.setUserAuthenticationRequired(true)
            builder.setInvalidatedByBiometricEnrollment(securityTier.shouldInvalidateOnEnrollment())

            val timeoutSeconds = securityTier.getAuthTimeoutSeconds()

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // Android 11+: Use new authentication parameters API
                val authTypes = if (securityTier.allowsDeviceCredentials()) {
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                } else {
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                }

                builder.setUserAuthenticationParameters(
                    if (timeoutSeconds == -1) 0 else timeoutSeconds,
                    authTypes
                )
            } else {
                // Android 10 and below: Use deprecated API
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(
                    if (timeoutSeconds == -1) -1 else timeoutSeconds
                )
            }
        } else {
            builder.setUserAuthenticationRequired(false)
        }

        // Try to use StrongBox if available (Android 9+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                builder.setIsStrongBoxBacked(true)
                keyGenerator.init(builder.build())
                return keyGenerator.generateKey()
            } catch (_: Exception) {
                // StrongBox not available, fall back to TEE
                builder.setIsStrongBoxBacked(false)
            }
        }

        // Fallback to TEE
        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    /**
     * Provision the master key with a specific security tier.
     * This should be called during initial key provisioning.
     *
     * @param securityTier The desired security tier
     * @throws IllegalStateException if key already exists
     */
    fun provisionMasterKey(securityTier: SecurityTier) {
        if (keyStore.containsAlias(MASTER_KEY_ALIAS)) {
            throw IllegalStateException("Master key already exists. Delete it first if you want to reprovision.")
        }
        createMasterKey(securityTier)
    }

    /**
     * Check if StrongBox is being used for the master key.
     */
    fun isUsingStrongBox(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return false
        }

        return try {
            val secretKey = keyStore.getKey(MASTER_KEY_ALIAS, null) as? SecretKey
            if (secretKey != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val factory = javax.crypto.SecretKeyFactory.getInstance(
                    secretKey.algorithm,
                    ANDROID_KEYSTORE
                )
                @Suppress("DEPRECATION")
                val keyInfo = factory.getKeySpec(
                    secretKey,
                    android.security.keystore.KeyInfo::class.java
                ) as android.security.keystore.KeyInfo
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    suspend fun <T> retryCrypto(c: (SecretKey) -> Cipher, op: (SecretKey, Cipher) -> T): Result<T, CryptoError> {
        val k = getMasterKey() ?: return Result.err(CryptoError.NoMasterKey)
        var cipher = c(k);
        while (true) {
            try {
                val result = op.invoke(k, cipher)
                return Result.Ok(result)
            } catch (e: Exception) {
                if (e is KeyPermanentlyInvalidatedException) {
                    return Result.err(CryptoError.KeyInvalidated)
                }

                val doBiometric = isUserNotAuthenticated(e) or doesKeyRequireAuth(k)

                if (doBiometric) {
                    // Recreate cipher
                    cipher = c(k);

                    if (biometricAuthManager.authenticate(
                            title = "Authenticate",
                            subtitle = "Access encrypted VPN configurations",
                            co = BiometricPrompt.CryptoObject(cipher),
                        )
                    ) {
                        continue;
                    } else {
                        return Result.err(CryptoError.AuthenticationFailure)
                    }
                }

                // We're out of idea
                return Result.err(CryptoError.Unknown(e))
            }
        }
    }

    /**
     * Encrypt data using AES-256-GCM.
     * May require biometric authentication depending on security tier.
     *
     * @param plaintext The data to encrypt
     * @return EncryptedData containing IV and ciphertext, or null if authentication failed
     * @throws javax.crypto.IllegalBlockSizeException if encryption fails
     */
    suspend fun encrypt(plaintext: String): Result<EncryptedData, CryptoError> {
        return retryCrypto({ k ->
            val c = Cipher.getInstance(TRANSFORMATION)
            c.init(Cipher.ENCRYPT_MODE, k)
            c
        }) { k, c ->
            val iv = c.iv
            val ciphertext = c.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            EncryptedData(iv, ciphertext)
        }
    }

    /**
     * Decrypt data using AES-256-GCM.
     * May require biometric authentication depending on security tier.
     *
     * @param encryptedData The encrypted data containing IV and ciphertext
     * @return Decrypted plaintext string, or null if authentication failed
     * @throws javax.crypto.AEADBadTagException if data has been tampered with
     */
    suspend fun decrypt(encryptedData: EncryptedData): Result<String, CryptoError> {
        return retryCrypto({ k->
            val c = Cipher.getInstance(TRANSFORMATION)
            c.init(
                Cipher.DECRYPT_MODE,
                k,
                GCMParameterSpec(GCM_TAG_LENGTH, encryptedData.iv)
            )
            c
        }) { k, c ->
            val plaintext = c.doFinal(encryptedData.ciphertext)
            String(plaintext, Charsets.UTF_8)
        }
    }

    /**
     * Decrypt data with nullable IV and ciphertext arrays.
     * Returns null if either parameter is null or if authentication failed.
     */
    suspend fun decrypt(iv: ByteArray?, ciphertext: ByteArray?): Result<String?, CryptoError> {
        if (iv == null || ciphertext == null) {
            return Result.Ok(null)
        }
        return decrypt(EncryptedData(iv, ciphertext)).map { it }
    }

    /**
     * Check if the master key exists.
     */
    fun isMasterKeyInitialized(): Boolean {
        return keyStore.containsAlias(MASTER_KEY_ALIAS)
    }

    /**
     * Delete the master key (for testing or reset purposes).
     * WARNING: This will make all encrypted data unrecoverable!
     */
    fun deleteMasterKey() {
        if (keyStore.containsAlias(MASTER_KEY_ALIAS)) {
            keyStore.deleteEntry(MASTER_KEY_ALIAS)
        }
    }
}

/**
 * Error type for crypto operations.
 */
sealed class CryptoError {
    object NoMasterKey : CryptoError() {
        override fun toString() = "No master key found"
    }

    object KeyInvalidated : CryptoError() {
        override fun toString() = "Master key has been invalidated\nPlease reset the storage"
    }

    object AuthenticationFailure : CryptoError() {
        override fun toString() = "Authentication failed"
    }

    data class Unknown(val exception: Exception) : CryptoError() {
        override fun toString() = "Unknown crypto error: " + exception.message
    }
}