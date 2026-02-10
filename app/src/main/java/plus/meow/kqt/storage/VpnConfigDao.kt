package plus.meow.kqt.storage

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Update
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Data Access Object for VPN configurations.
 */
@Dao
interface VpnConfigDao {

    /**
     * Get all VPN configurations (full entities including encrypted data).
     * Sorted by ID (UUIDv7, which is time-ordered) ASC for stable, chronological ordering.
     */
    @Query("SELECT * FROM vpn_configs ORDER BY id ASC")
    suspend fun getAll(): List<VpnConfigEntity>

    /**
     * Get all VPN configuration metadata (id and name only, no decryption needed).
     * @deprecated Use getAll() instead to avoid race conditions
     */
    @Deprecated("Use getAll() instead")
    @Query("SELECT id, name FROM vpn_configs ORDER BY id ASC")
    suspend fun getAllMetadata(): List<VpnConfigMetadata>


    /**
     * Get a specific VPN configuration by ID (includes encrypted data).
     */
    @Query("SELECT * FROM vpn_configs WHERE id = :id")
    suspend fun getById(id: Uuid): VpnConfigEntity?

    /**
     * Insert a new VPN configuration.
     */
    @Insert
    suspend fun insert(config: VpnConfigEntity)

    /**
     * Update an existing VPN configuration.
     * Updates all fields based on the entity's ID.
     */
    @Update
    suspend fun update(config: VpnConfigEntity)

    /**
     * Delete a VPN configuration by ID.
     */
    @Query("DELETE FROM vpn_configs WHERE id = :id")
    suspend fun deleteById(id: Uuid)

    /**
     * Delete all VPN configurations.
     */
    @Query("DELETE FROM vpn_configs")
    suspend fun deleteAll()
}

