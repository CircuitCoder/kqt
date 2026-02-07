package plus.meow.kqt.storage

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters

/**
 * Room database for VPN configurations.
 */
@Database(
    entities = [VpnConfigEntity::class],
    version = 2,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class VpnConfigDatabase : RoomDatabase() {

    abstract fun vpnConfigDao(): VpnConfigDao

    companion object {
        @Volatile
        private var INSTANCE: VpnConfigDatabase? = null

        fun getInstance(context: Context): VpnConfigDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    VpnConfigDatabase::class.java,
                    "vpn_configs_db"
                )
                    .fallbackToDestructiveMigration() // Drop and recreate on schema change
                    .build()
                INSTANCE = instance
                instance
            }
        }

        /**
         * Clear the database instance (used for testing or reset).
         */
        fun clearInstance() {
            synchronized(this) {
                INSTANCE = null
            }
        }
    }
}

