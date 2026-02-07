package plus.meow.kqt

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
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
            items = vpns,
            onEdit = ::showEditSheet,
            onToggle = ::setRunning
        )
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter

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
        adapter.updateRunningId(list, runningId)
    }

    private fun findEntryById(entryId: UUID): VPNEntry? {
        return vpns.firstOrNull { it.id == entryId }
    }

    private fun showEditSheet(entry: VPNEntry) {
        val entryId = entry.id
        val currentEntry = findEntryById(entryId) ?: return
        val dialog = BottomSheetDialog(this)
        val view = LayoutInflater.from(this).inflate(R.layout.sheet_edit_vpn, null)

        val nameInput = view.findViewById<TextInputEditText>(R.id.nameInput)
        val toggleButton = view.findViewById<MaterialButton>(R.id.toggleIconButton)
        val exportButton = view.findViewById<MaterialButton>(R.id.exportButton)
        val importButton = view.findViewById<MaterialButton>(R.id.importButton)
        val saveButton = view.findViewById<MaterialButton>(R.id.saveButton)
        val configText = view.findViewById<TextView>(R.id.configText)

        var draftName = currentEntry.name

        nameInput.setText(draftName)
        configText.text = currentEntry.cfg

        val hasNameConflict = { candidate: String ->
            vpns.any { it.id != entryId && it.name == candidate }
        }

        val updateNameError = { candidate: String ->
            val conflict = hasNameConflict(candidate)
            nameInput.error = if (conflict) getString(R.string.vpn_name_conflict) else null
            conflict
        }

        val updateSaveEnabled = {
            val changed = draftName != currentEntry.name
            val conflict = updateNameError(draftName)
            saveButton.isEnabled = changed && !conflict
        }

        toggleButton.isChecked = runningId == entryId
        updateSaveEnabled()

        nameInput.doAfterTextChanged { text ->
            draftName = text?.toString().orEmpty()
            updateSaveEnabled()
        }

        toggleButton.addOnCheckedChangeListener { btn, checked ->
            setRunning(entryId, checked)
        }

        exportButton.setOnClickListener {
            // TODO: hook export flow.
        }

        importButton.setOnClickListener {
            // TODO: hook import flow.
        }

        saveButton.setOnClickListener {
            if (!updateNameError(draftName)) {
                val target = findEntryById(entryId) ?: return@setOnClickListener
                target.name = draftName
                adapter.updateEntry(list, entryId)
                dialog.dismiss()
            }
        }

        dialog.setContentView(view)
        dialog.setOnShowListener {
            val sheet = dialog.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            if (sheet != null) {
                val behavior = BottomSheetBehavior.from(sheet)
                // Set peek height to show controls but hide most of the configuration
                // Two-stage expansion: collapsed (peek) -> full screen (no half-expanded state)
                val peekHeight = resources.getDimensionPixelSize(R.dimen.bottom_sheet_peek_height)
                behavior.peekHeight = peekHeight
                behavior.state = BottomSheetBehavior.STATE_COLLAPSED
                behavior.isFitToContents = true
                behavior.skipCollapsed = false

                // Set minimum height to screen height to cover backdrop when fully expanded
                val displayMetrics = resources.displayMetrics
                val screenHeight = displayMetrics.heightPixels
                view.minimumHeight = screenHeight
            }
        }
        dialog.show()
    }
}

data class VPNEntry(
    val id: UUID,
    var name: String,
    var cfg: String,
)

private class VpnAdapter(
    private val items: List<VPNEntry>,
    private val onEdit: (VPNEntry) -> Unit,
    private val onToggle: (UUID, Boolean) -> Unit,
) : RecyclerView.Adapter<VpnAdapter.VpnViewHolder>() {
    private var runningId: UUID? = null

    private companion object {
        const val PAYLOAD_RUNNING = "payload_running"
        const val PAYLOAD_NAME = "payload_name"
    }

    init {
        setHasStableIds(true)
    }

    fun updateRunningId(recyclerView: RecyclerView, id: UUID?) {
        val previousId = runningId
        runningId = id
        updateRow(recyclerView, previousId, PAYLOAD_RUNNING)
        if (id != previousId) {
            updateRow(recyclerView, id, PAYLOAD_RUNNING)
        }
    }

    fun updateEntry(recyclerView: RecyclerView, entryId: UUID) {
        updateRow(recyclerView, entryId, PAYLOAD_NAME)
    }

    override fun getItemId(position: Int): Long {
        val itemId = items[position].id
        return itemId.mostSignificantBits xor itemId.leastSignificantBits
    }

    override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): VpnViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_vpn, parent, false)
        return VpnViewHolder(view, onEdit, onToggle)
    }

    override fun onBindViewHolder(holder: VpnViewHolder, position: Int, payloads: MutableList<Any>) {
        if (payloads.isEmpty()) {
            onBindViewHolder(holder, position)
            return
        }

        val isRunning = runningId == items[position].id
        if (payloads.any { it == PAYLOAD_RUNNING }) {
            holder.updateRunning(isRunning)
        }
        if (payloads.any { it == PAYLOAD_NAME }) {
            holder.updateName(items[position].name)
        }
    }

    override fun onBindViewHolder(holder: VpnViewHolder, position: Int) {
        holder.bind(items[position], runningId == items[position].id)
    }

    override fun getItemCount(): Int = items.size

    private fun updateRow(recyclerView: RecyclerView, entryId: UUID?, payload: String) {
        if (entryId == null) {
            return
        }
        val index = items.indexOfFirst { it.id == entryId }
        if (index < 0) {
            return
        }
        val holder = recyclerView.findViewHolderForAdapterPosition(index) as? VpnViewHolder
        if (holder != null) {
            if (payload == PAYLOAD_RUNNING) {
                holder.updateRunning(runningId == items[index].id)
            } else if (payload == PAYLOAD_NAME) {
                holder.updateName(items[index].name)
            }
        } else {
            notifyItemChanged(index, payload)
        }
    }

    class VpnViewHolder(
        itemView: View,
        private val onEdit: (VPNEntry) -> Unit,
        private val onToggle: (UUID, Boolean) -> Unit,
    ) : RecyclerView.ViewHolder(itemView) {
        private val nameText = itemView.findViewById<TextView>(R.id.vpnName)
        private val toggle = itemView.findViewById<MaterialSwitch>(R.id.vpnToggle)
        private var currentEntryId: UUID? = null

        fun bind(entry: VPNEntry, isRunning: Boolean) {
            currentEntryId = entry.id
            nameText.text = entry.name
            itemView.setOnClickListener { onEdit(entry) }
            updateRunning(isRunning)
        }

        fun updateRunning(isRunning: Boolean) {
            toggle.setOnCheckedChangeListener(null)
            toggle.isChecked = isRunning
            applyToggleListener()
        }

        fun updateName(name: String) {
            nameText.text = name
        }

        private fun applyToggleListener() {
            val entryId = currentEntryId ?: return
            toggle.setOnCheckedChangeListener { _, checked ->
                onToggle(entryId, checked)
            }
        }
    }
}
