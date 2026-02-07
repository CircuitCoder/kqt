package plus.meow.kqt

import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.materialswitch.MaterialSwitch
import plus.meow.kqt.storage.VpnConfigEntity
import java.util.UUID

class VpnAdapter(
    private val onEdit: (VpnConfigEntity) -> Unit,
    private val onToggle: (UUID, Boolean) -> Unit,
) : ListAdapter<VpnConfigEntity, VpnAdapter.VpnViewHolder>(VpnDiffCallback()) {

    private var runningId: UUID? = null

    init {
        setHasStableIds(true)
    }

    fun updateRunningId(newRunningId: UUID?) {
        val previousId = runningId
        runningId = newRunningId

        // Only update affected items
        currentList.forEachIndexed { index, entry ->
            if (entry.id == previousId || entry.id == newRunningId) {
                notifyItemChanged(index, PAYLOAD_RUNNING)
            }
        }
    }


    override fun getItemId(position: Int): Long {
        val itemId = getItem(position).id
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

        val entry = getItem(position)
        val isRunning = runningId == entry.id
        val hasConfig = entry.encryptedConfig != null

        if (payloads.any { it == PAYLOAD_RUNNING }) {
            holder.updateRunning(isRunning, hasConfig)
        }
        if (payloads.any { it == PAYLOAD_NAME }) {
            holder.updateName(entry.name)
        }
    }

    override fun onBindViewHolder(holder: VpnViewHolder, position: Int) {
        val entry = getItem(position)
        val hasConfig = entry.encryptedConfig != null
        holder.bind(entry, runningId == entry.id, hasConfig)
    }

    class VpnViewHolder(
        itemView: View,
        private val onEdit: (VpnConfigEntity) -> Unit,
        private val onToggle: (UUID, Boolean) -> Unit,
    ) : RecyclerView.ViewHolder(itemView) {
        private val nameText = itemView.findViewById<TextView>(R.id.vpnName)
        private val toggle = itemView.findViewById<MaterialSwitch>(R.id.vpnToggle)
        private var currentEntryId: UUID? = null

        fun bind(entry: VpnConfigEntity, isRunning: Boolean, hasConfig: Boolean) {
            currentEntryId = entry.id
            nameText.text = entry.name
            itemView.setOnClickListener { onEdit(entry) }
            updateRunning(isRunning, hasConfig)
        }

        fun updateRunning(isRunning: Boolean, hasConfig: Boolean = true) {
            toggle.setOnCheckedChangeListener(null)
            toggle.isChecked = isRunning
            toggle.isEnabled = hasConfig
            applyToggleListener(hasConfig)
        }

        fun updateName(name: String) {
            nameText.text = name
        }

        private fun applyToggleListener(hasConfig: Boolean = true) {
            val entryId = currentEntryId ?: return
            if (hasConfig) {
                toggle.setOnCheckedChangeListener { _, checked ->
                    onToggle(entryId, checked)
                }
            } else {
                toggle.setOnCheckedChangeListener(null)
            }
        }
    }

    class VpnDiffCallback : DiffUtil.ItemCallback<VpnConfigEntity>() {
        override fun areItemsTheSame(oldItem: VpnConfigEntity, newItem: VpnConfigEntity): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(oldItem: VpnConfigEntity, newItem: VpnConfigEntity): Boolean {
            return oldItem.name == newItem.name &&
                   oldItem.encryptedConfig.contentEquals(newItem.encryptedConfig) &&
                   oldItem.iv.contentEquals(newItem.iv)
        }

        override fun getChangePayload(oldItem: VpnConfigEntity, newItem: VpnConfigEntity): Any? {
            return when {
                oldItem.name != newItem.name -> PAYLOAD_NAME
                else -> null
            }
        }
    }

    companion object {
        private const val PAYLOAD_RUNNING = "payload_running"
        private const val PAYLOAD_NAME = "payload_name"
    }
}

