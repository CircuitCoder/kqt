package plus.meow.kqt.storage

import android.security.keystore.UserNotAuthenticatedException
import androidx.room.Entity
import androidx.room.PrimaryKey
import plus.meow.kqt.crypto.CryptoManager
import plus.meow.kqt.utils.Result
import java.util.UUID

/**
 * Room entity representing a VPN configuration.
 *
 * @property id Unique identifier (randomly generated UUID)
 * @property name Human-readable name (stored in plaintext)
 * @property encryptedConfig Encrypted configuration data (AES-256-GCM), null if not yet configured
 * @property iv Initialization vector for GCM (12 bytes), null if not yet configured
 */
@Entity(tableName = "vpn_configs")
data class VpnConfigEntity(
    @PrimaryKey
    val id: UUID,
    val name: String,
    val encryptedConfig: ByteArray?,
    val iv: ByteArray?
) {
    // ...existing equals and hashCode...
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as VpnConfigEntity

        if (id != other.id) return false
        if (name != other.name) return false
        if (encryptedConfig != null && other.encryptedConfig != null) {
            if (!encryptedConfig.contentEquals(other.encryptedConfig)) return false
        } else if ((encryptedConfig == null) != (other.encryptedConfig == null)) {
            return false
        }
        if (iv != null && other.iv != null) {
            if (!iv.contentEquals(other.iv)) return false
        } else if ((iv == null) != (other.iv == null)) {
            return false
        }

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + (encryptedConfig?.contentHashCode() ?: 0)
        result = 31 * result + (iv?.contentHashCode() ?: 0)
        return result
    }

    /**
     * Error type for crypto operations.
     */
    sealed class CryptoError {
        object AuthenticationRequired : CryptoError() {
            override fun toString() = "Biometric authentication required"
        }

        data class Failed(val message: String, val exception: Exception? = null) : CryptoError() {
            override fun toString() = "Crypto error: $message"
        }
    }

    /**
     * Decrypt the configuration data.
     *
     * @param cryptoManager The crypto manager to use for decryption
     * @return Result.Ok with the config string (or null if not configured),
     *         Result.Err with CryptoError if authentication required or decryption failed
     */
    fun decryptConfig(cryptoManager: CryptoManager): Result<String?, CryptoError> {
        return try {
            val decrypted = cryptoManager.decrypt(iv, encryptedConfig)
            Result.ok(decrypted)
        } catch (_: UserNotAuthenticatedException) {
            Result.err(CryptoError.AuthenticationRequired)
        } catch (e: Exception) {
            Result.err(CryptoError.Failed("Failed to decrypt config: ${e.message}", e))
        }
    }

    /**
     * Create a copy of this entity with updated name and encrypted config.
     *
     * @param newName The new name
     * @param newConfig The new configuration string to encrypt
     * @param cryptoManager The crypto manager to use for encryption
     * @return Result.Ok with the updated entity,
     *         Result.Err with CryptoError if authentication required or encryption failed
     */
    fun withNameAndConfig(
        newName: String,
        newConfig: String,
        cryptoManager: CryptoManager
    ): Result<VpnConfigEntity, CryptoError> {
        return try {
            val encrypted = cryptoManager.encrypt(newConfig)
            val updated = this.copy(
                name = newName,
                encryptedConfig = encrypted.ciphertext,
                iv = encrypted.iv
            )
            Result.ok(updated)
        } catch (_: UserNotAuthenticatedException) {
            Result.err(CryptoError.AuthenticationRequired)
        } catch (e: Exception) {
            Result.err(CryptoError.Failed("Failed to update entity: ${e.message}", e))
        }
    }

    companion object {
        /**
         * Create a new VPN configuration entity with encrypted config.
         * Generates a new UUID automatically.
         *
         * @param name The human-readable name
         * @param config The configuration string to encrypt (null for no config)
         * @param cryptoManager The crypto manager to use for encryption
         * @return Result.Ok with the created entity,
         *         Result.Err with CryptoError if authentication required or encryption failed
         */
        fun create(
            name: String,
            config: String?,
            cryptoManager: CryptoManager
        ): Result<VpnConfigEntity, CryptoError> {
            return try {
                val (encryptedConfig, iv) = if (config != null) {
                    val encrypted = cryptoManager.encrypt(config)
                    encrypted.ciphertext to encrypted.iv
                } else {
                    null to null
                }

                val entity = VpnConfigEntity(
                    id = UUID.randomUUID(),
                    name = name,
                    encryptedConfig = encryptedConfig,
                    iv = iv
                )
                Result.ok(entity)
            } catch (_: UserNotAuthenticatedException) {
                Result.err(CryptoError.AuthenticationRequired)
            } catch (e: Exception) {
                Result.err(CryptoError.Failed("Failed to create entity: ${e.message}", e))
            }
        }
    }
}

/**
 * Simple data class for listing VPN configurations without decryption.
 */
data class VpnConfigMetadata(
    val id: UUID,
    val name: String
)

