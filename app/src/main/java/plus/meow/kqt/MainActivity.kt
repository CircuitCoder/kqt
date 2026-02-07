package plus.meow.kqt

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.util.UUID

class MainActivity : AppCompatActivity() {
    private val vpns = mutableListOf(
        VPNEntry(
            id = UUID.randomUUID(),
            name = "Test VPN1",
            cfg = "Test",
        ),
        VPNEntry(
            id = UUID.randomUUID(),
            name = "Test VPN2",
            cfg = "Test",
        ),
    )
    private var runningId: UUID? = null
    private lateinit var adapter: VpnAdapter
    private lateinit var list: RecyclerView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        list = findViewById(R.id.vpnList)
        adapter = VpnAdapter(
            onEdit = ::showEditSheet,
            onToggle = ::setRunning
        )
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter

        // Submit initial list
        adapter.submitList(vpns.toList())

        ViewCompat.setOnApplyWindowInsetsListener(list) { view, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(
                systemBars.left,
                systemBars.top,
                systemBars.right,
                systemBars.bottom
            )
            insets
        }
    }

    private fun setRunning(entryId: UUID, enabled: Boolean) {
        runningId = if (enabled) entryId else null
        adapter.updateRunningId(runningId)
    }

    private fun findEntryById(entryId: UUID): VPNEntry? {
        return vpns.firstOrNull { it.id == entryId }
    }

    private fun hasNameConflict(excludeId: UUID, name: String): Boolean {
        return vpns.any { it.id != excludeId && it.name == name }
    }

    private fun showEditSheet(entry: VPNEntry) {
        val sheet = EditVpnBottomSheet.newInstance(
            entryId = entry.id,
            isRunning = runningId == entry.id,
            entryProvider = ::findEntryById,
            nameValidator = { id, name -> !hasNameConflict(id, name) },
            onSave = ::saveEntryName,
            onToggle = ::setRunning
        )
        sheet.show(supportFragmentManager, "edit_vpn")
    }

    private fun saveEntryName(entryId: UUID, newName: String) {
        val entry = findEntryById(entryId) ?: return
        entry.name = newName
        // Submit updated list to trigger DiffUtil
        adapter.submitList(vpns.toList())
    }
}
