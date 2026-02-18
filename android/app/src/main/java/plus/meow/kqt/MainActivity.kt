package plus.meow.kqt

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
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
import plus.meow.kqt.vpn.VpnStateManager
import kotlin.uuid.Uuid

class MainActivity : AppCompatActivity() {
    private val vpns = mutableListOf<VpnConfigEntity>()
    private lateinit var adapter: VpnAdapter
    private lateinit var list: RecyclerView
    private lateinit var emptyStateHint: TextView
    private lateinit var provisioningManager: KeyProvisioningManager
    private lateinit var repository: VpnConfigRepository
    private lateinit var cryptoManager: CryptoManager
    private lateinit var vpnStateManager: VpnStateManager
    private var loadEpoch: Int = 0

    // Track pending VPN connection that requires permission
    private var pendingVpnConnection: VpnConfigEntity? = null

    // VPN permission launcher
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            // Permission granted, retry connection
            pendingVpnConnection?.let { vpn ->
                toggleVpn(vpn, true)
            }
        } else {
            // Permission denied
            android.widget.Toast.makeText(
                this,
                "VPN permission denied",
                android.widget.Toast.LENGTH_SHORT
            ).show()
        }
        pendingVpnConnection = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize provisioning manager
        provisioningManager = KeyProvisioningManager(this)

        // Initialize crypto manager and repository
        val database = VpnConfigDatabase.getInstance(this)
        cryptoManager = CryptoManager(this, provisioningManager)
        repository = VpnConfigRepository(database.vpnConfigDao())
        vpnStateManager = VpnStateManager(this, cryptoManager)

        // Set up VPN permission callback
        vpnStateManager.onPermissionRequired = { intent ->
            vpnPermissionLauncher.launch(intent)
        }

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
            lifecycleOwner = this,
            vpnStateManager = vpnStateManager,
            onEdit = ::showEditSheet,
            onToggle = ::toggleVpn,
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
            loadVpnListAndWait()
        }
    }

    private suspend fun loadVpnListAndWait() {
        // Capture epoch at start
        val currentEpoch = ++loadEpoch

        // Perform all suspendable operations first
        val allVpns = repository.listAll()

        // Check if we're still the latest load
        if (currentEpoch != loadEpoch) {
            return // Newer load started, discard this result
        }

        // Now update UI state atomically
        vpns.clear()
        vpns.addAll(allVpns)
        adapter.submitList(vpns.toList())

        // Show/hide empty state hint
        emptyStateHint.visibility = if (vpns.isEmpty()) View.VISIBLE else View.GONE
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
            val entity = repository.createEmpty(uniqueName).unwrapOrElse {
                Result.Err<Unit, _>(it).toast(this@MainActivity)
                return@launch
            }

            // Open edit sheet for the new VPN
            showEditSheet(entity)

            // Fetch the newly created entry directly from the repository
            loadVpnListAndWait()
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

    private fun toggleVpn(vpn: VpnConfigEntity, enabled: Boolean) {
        lifecycleScope.launch {
            val coro = if (enabled) {
                // Store pending connection in case permission is needed
                pendingVpnConnection = vpn
                vpnStateManager.connect(vpn)
            } else {
                vpnStateManager.disconnect(vpn.id)
            }

            coro.unwrapOrElse {
                // Only clear pending connection if it's not a permission error
                // (permission error will be handled by the launcher callback)
                if (it !is plus.meow.kqt.vpn.VpnStateError.PermissionRequired) {
                    pendingVpnConnection = null
                    android.widget.Toast.makeText(
                        this@MainActivity,
                        "Failed to ${if (enabled) "connect" else "disconnect"}: $it",
                        android.widget.Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }

    private fun validateVpnName(excludeId: Uuid, name: String): String? {
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
            repository = repository,
            cryptoManager = cryptoManager,
            vpnStateManager = vpnStateManager,
            nameValidator = { this.validateVpnName(entry.id, it) },
            onChanged = ::loadVpnList,
            onToggle = { this.toggleVpn(entry, it) }
        )
        sheet.show(supportFragmentManager, "edit_vpn")
    }
}
