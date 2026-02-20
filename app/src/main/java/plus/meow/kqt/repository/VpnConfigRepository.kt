package plus.meow.kqt.repository

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import plus.meow.kqt.storage.VpnConfigDao
import plus.meow.kqt.storage.VpnConfigEntity
import plus.meow.kqt.storage.VpnConfigMetadata
import plus.meow.kqt.utils.Result
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Repository for VPN configuration storage with encryption.
 *
 * Provides high-level operations for managing encrypted VPN configurations.
 */
class VpnConfigRepository(
    private val dao: VpnConfigDao
) {

    /**
     * Error type for database operations.
     */
    data class DatabaseError(val message: String, val exception: Exception? = null) {
        override fun toString() = "Database error: $message"
    }

    /**
     * Get specific VPN configuration
     */
    suspend fun get(id: Uuid) = withContext(Dispatchers.IO) {
        dao.getById(id)
    }

    /**
     * List all VPN configurations (full entities).
     */
    suspend fun listAll(): List<VpnConfigEntity> = withContext(Dispatchers.IO) {
        dao.getAll()
    }

    /**
     * Update a VPN configuration entity.
     */
    suspend fun update(entity: VpnConfigEntity): Result<Unit, DatabaseError> = withContext(Dispatchers.IO) {
        try {
            dao.update(entity)
            Result.ok(Unit)
        } catch (e: Exception) {
            Result.err(DatabaseError("Failed to update entity: ${e.message}", e))
        }
    }

    /**
     * Create a new empty VPN configuration.
     */
    suspend fun createEmpty(name: String): Result<VpnConfigEntity, DatabaseError> = withContext(Dispatchers.IO) {
        try {
            val id = Uuid.generateV7()
            val entity = VpnConfigEntity(
                id = id,
                name = name,
                encryptedConfig = null,
                iv = null
            )
            dao.insert(entity)
            Result.ok(entity)
        } catch (e: Exception) {
            Result.err(DatabaseError("Failed to create empty config: ${e.message}", e))
        }
    }

    /**
     * Delete a VPN configuration.
     */
    suspend fun delete(id: Uuid): Result<Unit, DatabaseError> = withContext(Dispatchers.IO) {
        try {
            dao.deleteById(id)
            Result.ok(Unit)
        } catch (e: Exception) {
            Result.err(DatabaseError("Failed to delete config: ${e.message}", e))
        }
    }

    /**
     * Get metadata for a specific VPN configuration.
     */
    suspend fun getMetadata(id: Uuid): Result<VpnConfigMetadata, DatabaseError> = withContext(Dispatchers.IO) {
        try {
            val entity = dao.getById(id)
                ?: return@withContext Result.err(DatabaseError("VPN configuration not found"))

            Result.ok(VpnConfigMetadata(entity.id, entity.name))
        } catch (e: Exception) {
            Result.err(DatabaseError("Failed to get metadata: ${e.message}", e))
        }
    }
}
