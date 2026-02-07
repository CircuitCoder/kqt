package plus.meow.kqt.storage

import androidx.room.TypeConverter
import java.util.UUID

/**
 * Type converters for Room to handle UUID.
 */
class Converters {
    @TypeConverter
    fun fromUUID(uuid: UUID): String {
        return uuid.toString()
    }

    @TypeConverter
    fun toUUID(uuidString: String): UUID {
        return UUID.fromString(uuidString)
    }
}

