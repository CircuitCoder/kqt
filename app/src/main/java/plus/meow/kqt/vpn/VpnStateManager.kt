package plus.meow.kqt.vpn

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import plus.meow.kqt.crypto.CryptoError
import plus.meow.kqt.crypto.CryptoManager
import plus.meow.kqt.storage.VpnConfigEntity
import plus.meow.kqt.utils.Result
import uniffi.kqt.ConfigParseException
import kotlin.uuid.Uuid

/**
 * VPN connection state for a single VPN tunnel.
 */
sealed class VpnState {
    abstract fun ident(): Int

    companion object {
        val IDENT_DISCONNECTED: Int = 1
        val IDENT_CONNECTING: Int = 2
        val IDENT_CONNECTED: Int = 4
    }

    /** VPN is disconnected and not running */
    object Disconnected : VpnState() {
        override fun ident(): Int{
            return IDENT_DISCONNECTED
        }
    }

    /** VPN is in the process of connecting */
    object Connecting : VpnState() {
        override fun ident(): Int{
            return IDENT_CONNECTING
        }
    }


    /** VPN is connected and running with the given handle */
    data class Connected(val handle: VpnLifecycleHandle) : VpnState() {
        override fun ident(): Int {
            return IDENT_CONNECTED
        }
    }
}

/**
 * Errors that can occur during VPN state operations.
 */
sealed class VpnStateError {
    /** Attempted state transition is inconsistent with current state */
    data class InconsistentState(
        val vpnId: Uuid,
        val from: VpnState,
        val to: VpnState,
    ) : VpnStateError() {
        override fun toString() = "Inconsistent state: VPN $vpnId unable $from -> $to"
    }

    /** Failed to decrypt configuration */
    data class ConfigDecryptFailed(val e: CryptoError) : VpnStateError() {
        override fun toString() = "Failed to decrypt configuration: $e"
    }

    /** Failed to parse configuration */
    data class ConfigParsingFailed(val e: ConfigParseException) : VpnStateError() {
        override fun toString() = "Failed to parse configuration: $e"
    }

    /** No configuration available (encrypted config is null) */
    data object ConfigNotFound : VpnStateError() {
        override fun toString() = "No configuration available"
    }

    /** Failed to bind to VPN service */
    data class ServiceBindFailed(val e: Exception) : VpnStateError() {
        override fun toString() = "Failed to bind to VPN service: $e"
    }

    /** VPN permission not granted */
    object PermissionRequired : VpnStateError() {
        override fun toString() = "VPN permission required. Please enable VPN in system settings."
    }
}

/**
 * Thread-safe state map with atomic compare-and-swap operations.
 */
private class AtomicStateMap {
    private val map = MutableStateFlow(mapOf<Uuid, VpnState>())

    /**
     * Get the current state for a VPN.
     * Returns Disconnected if not in map.
     */
    fun get(vpnId: Uuid): VpnState {
        return map.value[vpnId] ?: VpnState.Disconnected
    }

    /**
     * Attempt to atomically transition from expectedState to newState.
     * Returns true if successful, false if current state doesn't match expected.
     */
    fun compareAndSetOrGet(vpnId: Uuid, origMask: Int, newState: VpnState): VpnState? {
        var returned: VpnState? = null
        map.update { map ->
            val currentState = map[vpnId] ?: VpnState.Disconnected
            if (currentState.ident() and origMask == 0) {
                returned = currentState
                map
            } else {
                map + (vpnId to newState)
            }
        }
        return returned
    }

    /**
     * Unconditionally set the state for a VPN.
     */
    fun set(vpnId: Uuid, newState: VpnState) {
        map.update { it + (vpnId to newState) }
    }

    fun observe(vpnId: Uuid): Flow<VpnState> {
        return map.map { it[vpnId] ?: VpnState.Disconnected }.distinctUntilChanged()
    }
}

/**
 * Manages the state of all VPN tunnels in the application.
 *
 * This class provides:
 * - State tracking for all VPN connections (disconnected, connected, disconnecting)
 * - Observable state updates per VPN UUID
 * - Thread-safe state transitions
 * - Connection/disconnection operations with consistency checking
 */
class VpnStateManager(
    private val context: Context,
    private val cryptoManager: CryptoManager
) {
    companion object {
        private const val TAG = "VpnStateManager"
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    // Atomic state map for thread-safe compare-and-swap operations
    private val stateMap = AtomicStateMap()

    // VPN manager instance (lazily initialized)
    private var vpnManager: VpnManager? = null

    // Backend bridge (lazily initialized)
    private var backendBridge: VpnBackendBridge? = null

    /**
     * Get an observable state for a specific VPN.
     *
     * @param vpnId The UUID of the VPN
     * @return StateFlow that emits the current state of the VPN
     */
    fun observe(vpnId: Uuid): Flow<VpnState> {
        return stateMap.observe(vpnId)
    }

    /**
     * Get the current state of a VPN.
     *
     * @param vpnId The UUID of the VPN
     * @return The current VpnState
     */
    fun getState(vpnId: Uuid): VpnState {
        return stateMap.get(vpnId)
    }

    /**
     * Callback for requesting VPN permission.
     * The callback receives the permission intent that should be launched.
     */
    var onPermissionRequired: ((android.content.Intent) -> Unit)? = null

    /**
     * Connect a VPN.
     *
     * @param vpn The VPN configuration entity to connect
     * @return Result indicating success or error
     */
    suspend fun connect(vpn: VpnConfigEntity): Result<Unit, VpnStateError> {
        stateMap.compareAndSetOrGet(vpn.id, VpnState.IDENT_DISCONNECTED, VpnState.Connecting)?.also { cur ->
            return@connect Result.err(VpnStateError.InconsistentState(vpn.id, cur, VpnState.Connecting))
        }

        // Decrypt configuration
        val decryptedConfig = vpn.decryptConfig(cryptoManager).unwrapOrElse { error ->
            stateMap.set(vpn.id, VpnState.Disconnected)
            return Result.err(VpnStateError.ConfigDecryptFailed(error))
        }

        if (decryptedConfig == null) {
            stateMap.set(vpn.id, VpnState.Disconnected)
            return Result.err(VpnStateError.ConfigNotFound)
        }

        val parsedConfig = try {
            uniffi.kqt.ParsedConfig.parse(decryptedConfig)
        } catch (e: ConfigParseException) {
            stateMap.set(vpn.id, VpnState.Disconnected)
            return Result.err(VpnStateError.ConfigParsingFailed(e))
        }

        // Initialize VPN manager if needed
        val manager = vpnManager ?: VpnManager.getInstance(context).also {
            vpnManager = it
        }

        // Bind to VPN service
        try {
            manager.bind()
        } catch (e: Exception) {
            stateMap.set(vpn.id, VpnState.Disconnected)
            return Result.err(VpnStateError.ServiceBindFailed(e))
        }

        // Check VPN permission
        val permissionIntent = manager.checkPermission()
        if (permissionIntent != null) {
            // Invoke callback to request permission
            onPermissionRequired?.invoke(permissionIntent)
            stateMap.set(vpn.id, VpnState.Disconnected)
            return Result.err(VpnStateError.PermissionRequired)
        }

        // Initialize backend bridge if needed
        val bridge = backendBridge ?: VpnBackendBridge(manager).also {
            backendBridge = it
        }

        // Start VPN connection asynchronously
        scope.launch(Dispatchers.IO) {
            try {
                Log.i(TAG, "Starting VPN connection for ${vpn.id}")

                // Start backend and wait for termination
                val handle = bridge.startVpnWithBackend(parsedConfig, scope).unwrapOrElse {
                    Log.e(TAG, "Failed to start backend: $it")
                    stateMap.set(vpn.id, VpnState.Disconnected)
                    return@launch
                }

                stateMap.compareAndSetOrGet(vpn.id, VpnState.Connecting.ident(), VpnState.Connected(handle))?.also {
                    // State changed unexpectedly (e.g., user cancelled), stop the VPN
                    Log.w(TAG, "VPN ${vpn.id} state changed during connection, now is $it, stopping")
                    handle.vpnInstance.stop()
                    return@launch
                }

                Log.i(TAG, "VPN connection established for ${vpn.id}")
                val ret = handle.terminationJob.await()
                Log.i(TAG, "VPN ${vpn.id}: ${ret.toString()}")
            } catch (e: Exception) {
                Log.e(TAG, "Unexpected error during VPN connection: ${e.message}", e)
            } finally {
                val prev = stateMap.compareAndSetOrGet(vpn.id, VpnState.IDENT_CONNECTING or VpnState.IDENT_CONNECTED, VpnState.Disconnected)
                if (prev != null) {
                    Log.w(TAG, "VPN ${vpn.id} unexpected state during cleanup: was $prev, expected Connecting or Connected")
                }
            }
        }

        return Result.ok(Unit)
    }

    /**
     * Disconnect a VPN.
     *
     * @param vpnId The UUID of the VPN to disconnect
     * @return Result indicating success or error
     */
    fun disconnect(vpnId: Uuid): Result<Unit, VpnStateError> {
        // Atomically transition from Connected to Disconnecting
        val state = stateMap.get(vpnId)
        val handle = if (state is VpnState.Connected) {
            state.handle
        } else {
            return Result.Err(VpnStateError.InconsistentState(vpnId, state, VpnState.Disconnected))
        }

        Log.i(TAG, "Disconnecting VPN $vpnId")
        try {
            handle.vpnInstance.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping VPN instance: ${e.message}", e)
        }

        return Result.ok(Unit)
    }

    /**
     * Unbind from VPN service (cleanup).
     */
    fun cleanup() {
        vpnManager?.unbind()
        vpnManager = null
        backendBridge = null
    }
}