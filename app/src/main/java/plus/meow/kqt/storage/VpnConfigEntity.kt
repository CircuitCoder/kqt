package plus.meow.kqt.storage

import androidx.room.Entity
import androidx.room.PrimaryKey
import plus.meow.kqt.crypto.CryptoError
import plus.meow.kqt.crypto.CryptoManager
import plus.meow.kqt.utils.Result
import kotlin.uuid.Uuid

/**
 * Room entity representing a VPN configuration.
 *
 * @property id Unique identifier (UUIDv7 for time-ordered sorting)
 * @property name Human-readable name (stored in plaintext)
 * @property encryptedConfig Encrypted configuration data (AES-256-GCM), null if not yet configured
 * @property iv Initialization vector for GCM (12 bytes), null if not yet configured
 */
@Entity(tableName = "vpn_configs")
data class VpnConfigEntity(
    @PrimaryKey
    val id: Uuid,
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
     * Decrypt the configuration data.
     *
     * @param cryptoManager The crypto manager to use for decryption
     * @return Result.Ok with the config string (or null if not configured),
     *         Result.Err with CryptoError if authentication failed or decryption failed
     */
    suspend fun decryptConfig(cryptoManager: CryptoManager): Result<String?, CryptoError> {
        return cryptoManager.decrypt(iv, encryptedConfig)
    }

    /**
     * Create a copy of this entity with updated name and encrypted config.
     *
     * @param newName The new name
     * @param newConfig The new configuration string to encrypt
     * @param cryptoManager The crypto manager to use for encryption
     * @return Result.Ok with the updated entity,
     *         Result.Err with CryptoError if authentication failed or encryption failed
     */
    suspend fun withNameAndConfig(
        newName: String,
        newConfig: String,
        cryptoManager: CryptoManager
    ): Result<VpnConfigEntity, CryptoError> {
        return cryptoManager.encrypt(newConfig).map { encrypted ->
                this.copy(
                    name = newName,
                    encryptedConfig = encrypted.ciphertext,
                    iv = encrypted.iv
                )
            }
    }

    companion object {
        /**
         * Create a new VPN configuration entity with encrypted config.
         * Generates a new UUIDv7 automatically for time-ordered sorting.
         *
         * @param name The human-readable name
         * @param config The configuration string to encrypt (null for no config)
         * @param cryptoManager The crypto manager to use for encryption
         * @return Result.Ok with the created entity,
         *         Result.Err with CryptoError if authentication failed or encryption failed
         */
        suspend fun create(
            name: String,
            config: String?,
            cryptoManager: CryptoManager
        ): Result<VpnConfigEntity, CryptoError> {
            val initial = VpnConfigEntity(
                id = Uuid.generateV7(),
                name = name,
                encryptedConfig = null,
                iv = null
            )

            if (config == null) {
                return Result.Ok(initial)
            }

            return initial.withNameAndConfig(name, config, cryptoManager)
        }
    }
}

/**
 * Simple data class for listing VPN configurations without decryption.
 */
data class VpnConfigMetadata(
    val id: Uuid,
    val name: String
)

