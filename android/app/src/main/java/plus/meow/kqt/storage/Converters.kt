package plus.meow.kqt.storage

import androidx.room.TypeConverter
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Type converters for Room to handle Uuid.
 */
class Converters {
    @TypeConverter
    fun fromUuid(uuid: Uuid): String {
        return uuid.toString()
    }

    @TypeConverter
    fun toUuid(uuidString: String): Uuid {
        return Uuid.parse(uuidString)
    }
}

