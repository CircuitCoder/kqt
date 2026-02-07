package plus.meow.kqt

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.appbar.MaterialToolbar
import kotlinx.coroutines.launch
import plus.meow.kqt.crypto.CryptoManager
import plus.meow.kqt.crypto.KeyProvisioningManager
import plus.meow.kqt.repository.VpnConfigRepository
import plus.meow.kqt.storage.VpnConfigDatabase
import plus.meow.kqt.storage.VpnConfigEntity
import plus.meow.kqt.utils.Result
import java.util.UUID

class MainActivity : AppCompatActivity() {
    private val vpns = mutableListOf<VpnConfigEntity>()
    private var runningId: UUID? = null
    private lateinit var adapter: VpnAdapter
    private lateinit var list: RecyclerView
    private lateinit var emptyStateHint: TextView
    private lateinit var provisioningManager: KeyProvisioningManager
    private lateinit var repository: VpnConfigRepository
    private lateinit var cryptoManager: CryptoManager
    private var loadEpoch: Int = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize provisioning manager
        provisioningManager = KeyProvisioningManager(this)

        // Initialize crypto manager and repository
        val database = VpnConfigDatabase.getInstance(this)
        cryptoManager = CryptoManager(this, provisioningManager)
        repository = VpnConfigRepository(database.vpnConfigDao())

        // Check if key is provisioned, if not, launch provisioning activity
        if (!provisioningManager.isProvisioned()) {
            val intent = Intent(this, KeyProvisioningActivity::class.java)
            startActivity(intent)
            // Don't finish() here - let user see the main screen after provisioning
        }

        setContentView(R.layout.activity_main)

        // Set up toolbar
        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)

        list = findViewById(R.id.vpnList)
        emptyStateHint = findViewById(R.id.emptyStateHint)
        adapter = VpnAdapter(
            onEdit = ::showEditSheet,
            onToggle = ::setRunning
        )
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter

        // Load VPN list from database
        loadVpnList()
    }

    override fun onResume() {
        super.onResume()
        // Reload list when returning to activity
        loadVpnList()
    }

    private fun loadVpnList() {
        lifecycleScope.launch {
            // Capture epoch at start
            val currentEpoch = ++loadEpoch

            // Perform all suspendable operations first
            val allVpns = repository.listAll()

            // Check if we're still the latest load
            if (currentEpoch != loadEpoch) {
                return@launch // Newer load started, discard this result
            }

            // Now update UI state atomically
            vpns.clear()
            vpns.addAll(allVpns)
            adapter.submitList(vpns.toList())

            // Clear runningId if the running VPN no longer exists
            if (runningId != null && vpns.none { it.id == runningId }) {
                runningId = null
                adapter.updateRunningId(null)
            }

            // Show/hide empty state hint
            emptyStateHint.visibility = if (vpns.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_add -> {
                addNewVpn()
                true
            }
            R.id.action_settings -> {
                // Launch settings activity
                val intent = Intent(this, SettingsActivity::class.java)
                startActivity(intent)
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun addNewVpn() {
        lifecycleScope.launch {
            // Generate unique name
            val baseName = "New Connection"
            val uniqueName = generateUniqueName(baseName)

            // Create empty VPN in database
            val newId = when (val result = repository.createEmpty(uniqueName)) {
                is Result.Ok -> result.value
                is Result.Err -> {
                    result.toast(this@MainActivity)
                    return@launch
                }
            }

            // Reload the list to include the new VPN
            loadVpnList()

            // Open edit sheet for the new VPN
            val newEntry = vpns.firstOrNull { it.id == newId }
            if (newEntry != null) {
                showEditSheet(newEntry)
            }
        }
    }

    private fun generateUniqueName(baseName: String): String {
        val existingNames = vpns.map { it.name }.toSet()

        // Check if base name is available
        if (baseName !in existingNames) {
            return baseName
        }

        // Find next available number
        var counter = 2
        while (true) {
            val candidateName = "$baseName ($counter)"
            if (candidateName !in existingNames) {
                return candidateName
            }
            counter++
        }
    }

    private fun setRunning(entryId: UUID, enabled: Boolean) {
        runningId = if (enabled) entryId else null
        adapter.updateRunningId(runningId)
    }

    private fun validateVpnName(excludeId: UUID, name: String): String? {
        return when {
            name != name.trim() -> getString(R.string.vpn_name_empty) // Untrimmed
            name.isEmpty() -> getString(R.string.vpn_name_empty)
            name.length > 50 -> getString(R.string.vpn_name_too_long)
            vpns.any { it.id != excludeId && it.name == name } -> getString(R.string.vpn_name_conflict)
            else -> null
        }
    }

    private fun showEditSheet(entry: VpnConfigEntity) {
        val sheet = EditVpnBottomSheet.newInstance(
            entity = entry,
            isRunning = runningId == entry.id,
            repository = repository,
            cryptoManager = cryptoManager,
            nameValidator = ::validateVpnName,
            onChanged = ::loadVpnList,
            onToggle = ::setRunning
        )
        sheet.show(supportFragmentManager, "edit_vpn")
    }
}
