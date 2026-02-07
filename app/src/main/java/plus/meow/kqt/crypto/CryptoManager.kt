package plus.meow.kqt.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages encryption/decryption using Android Keystore.
 *
 * Uses a single master AES-256-GCM key stored in the best available keystore backend
 * (StrongBox if available, otherwise TEE).
 */
class CryptoManager {

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
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    /**
     * Get or create the master encryption key.
     * This key is stored in the best available keystore backend (StrongBox or TEE).
     *
     * @param securityTier Optional security tier for key creation. Only used when creating a new key.
     */
    private fun getOrCreateMasterKey(securityTier: SecurityTier = SecurityTier.TIMEOUT_5_MIN): SecretKey {
        if (keyStore.containsAlias(MASTER_KEY_ALIAS)) {
            return keyStore.getKey(MASTER_KEY_ALIAS, null) as SecretKey
        }

        return createMasterKey(securityTier)
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

    /**
     * Encrypt data using AES-256-GCM.
     * Requires biometric authentication (with 120-second timeout).
     *
     * @param plaintext The data to encrypt
     * @return EncryptedData containing IV and ciphertext
     * @throws javax.crypto.IllegalBlockSizeException if encryption fails
     * @throws android.security.keystore.UserNotAuthenticatedException if user needs to authenticate
     */
    fun encrypt(plaintext: String): EncryptedData {
        val masterKey = getOrCreateMasterKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)

        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

        return EncryptedData(iv, ciphertext)
    }

    /**
     * Decrypt data using AES-256-GCM.
     * Requires biometric authentication (with 120-second timeout).
     *
     * @param encryptedData The encrypted data containing IV and ciphertext
     * @return Decrypted plaintext string
     * @throws javax.crypto.AEADBadTagException if data has been tampered with
     * @throws android.security.keystore.UserNotAuthenticatedException if user needs to authenticate
     */
    fun decrypt(encryptedData: EncryptedData): String {
        val masterKey = getOrCreateMasterKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(GCM_TAG_LENGTH, encryptedData.iv))

        val plaintext = cipher.doFinal(encryptedData.ciphertext)
        return String(plaintext, Charsets.UTF_8)
    }

    /**
     * Decrypt data with nullable IV and ciphertext arrays.
     * Returns null if either parameter is null.
     */
    fun decrypt(iv: ByteArray?, ciphertext: ByteArray?): String? {
        if (iv == null || ciphertext == null) {
            return null
        }
        return decrypt(EncryptedData(iv, ciphertext))
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

