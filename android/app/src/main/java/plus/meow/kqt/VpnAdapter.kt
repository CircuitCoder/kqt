package plus.meow.kqt

import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.materialswitch.MaterialSwitch
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import plus.meow.kqt.storage.VpnConfigEntity
import plus.meow.kqt.vpn.VpnState
import plus.meow.kqt.vpn.VpnStateManager

class VpnAdapter(
    private val lifecycleOwner: LifecycleOwner,
    private val vpnStateManager: VpnStateManager,
    private val onEdit: (VpnConfigEntity) -> Unit,
    private val onToggle: (VpnConfigEntity, Boolean) -> Unit,
) : ListAdapter<VpnConfigEntity, VpnAdapter.VpnViewHolder>(VpnDiffCallback()) {

    init {
        setHasStableIds(true)
    }

    override fun getItemId(position: Int): Long {
        val itemId = getItem(position).id
        return itemId.hashCode().toLong()
    }

    override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): VpnViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_vpn, parent, false)
        return VpnViewHolder(view, lifecycleOwner, vpnStateManager, onEdit, onToggle)
    }

    override fun onBindViewHolder(holder: VpnViewHolder, position: Int) {
        val entry = getItem(position)
        holder.bind(entry)
    }

    class VpnViewHolder(
        itemView: View,
        private val lifecycleOwner: LifecycleOwner,
        private val vpnStateManager: VpnStateManager,
        private val onEdit: (VpnConfigEntity) -> Unit,
        private val onToggle: (VpnConfigEntity, Boolean) -> Unit,
    ) : RecyclerView.ViewHolder(itemView) {
        private val nameText = itemView.findViewById<TextView>(R.id.vpnName)
        private val toggle = itemView.findViewById<MaterialSwitch>(R.id.vpnToggle)
        private var currentEntry: VpnConfigEntity? = null
        private var stateObserverJob: kotlinx.coroutines.Job? = null

        fun bind(entry: VpnConfigEntity) {
            // Cancel previous flow subscription if any
            stateObserverJob?.cancel()

            currentEntry = entry

            // Update name
            nameText.text = entry.name

            // Update click listener
            itemView.setOnClickListener { onEdit(entry) }

            toggle.setOnClickListener {
                val entry = this.currentEntry
                if (!toggle.isEnabled or (entry == null)) return@setOnClickListener;

                val isChecked = toggle.isChecked
                toggle.isChecked = !isChecked
                if (entry!!.encryptedConfig != null) {
                    onToggle(entry, isChecked)
                }
            }

            // Observe VPN state for this entry
            stateObserverJob = vpnStateManager.observe(entry.id)
                .onEach { state ->
                    val isRunning = state !is VpnState.Disconnected
                    // Use entry from the captured scope, which is the entry we're currently bound to
                    updateToggle(isRunning)
                }
                .launchIn(lifecycleOwner.lifecycleScope)
        }

        private fun updateToggle(isRunning: Boolean) {
            toggle.isChecked = isRunning
            toggle.isEnabled = this.currentEntry?.encryptedConfig != null
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
    }
}

