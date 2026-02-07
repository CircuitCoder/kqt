package plus.meow.kqt

import java.util.UUID

data class VPNEntry(
    val id: UUID,
    var name: String,
    var cfg: String,
)

