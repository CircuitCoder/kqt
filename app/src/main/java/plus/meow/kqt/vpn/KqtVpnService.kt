package plus.meow.kqt.vpn

import android.annotation.SuppressLint
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.util.Log
import plus.meow.kqt.utils.Result

/**
 * Android VPN Service implementation for KQT.
 *
 * This service manages the actual VPN connection and communicates with
 * the VpnManager to coordinate VPN instance lifecycle.
 */
@SuppressLint("VpnServicePolicy")
class KqtVpnService : VpnService() {

    private val binder = LocalBinder()
    private var currentInstance: VpnInstance? = null

    inner class LocalBinder : Binder() {
        fun getService(): KqtVpnService = this@KqtVpnService
    }

    override fun onBind(intent: Intent?): IBinder {
        if (intent != null && SERVICE_INTERFACE == intent.action) {
            // Crucial: Let the VpnService return its internal Binder so onRevoke works
            return super.onBind(intent) ?: binder
        }
        return binder
    }

    override fun onRevoke() {
        super.onRevoke()
        Log.i(TAG, "VPN service revoked by system")
        currentInstance?.notifyTermination(VpnInstance.TerminationReason.ServiceRevoked)
        currentInstance = null
        stopSelf()
    }

    /**
     * Create a new VPN tunnel with the given configuration.
     *
     * If a VPN is already active, it will be stopped and replaced.
     *
     * @param config The VPN configuration
     * @return Result with VpnInstance on success, or VpnError on failure
     */
    fun createTunnel(config: VpnConfig): Result<VpnInstance, VpnError> {
        try {
            // Stop any existing VPN instance
            currentInstance?.let { existing ->
                Log.i(TAG, "Replacing existing VPN instance")
                existing.notifyTermination(VpnInstance.TerminationReason.ReplacedByAnother)
            }

            // Build the VPN interface
            val builder = Builder()

            // Add the application itself as an excluded application
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(TAG, "Excluded application: $packageName")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to exclude application: ${e.message}")
            }

            // Set MTU
            builder.setMtu(config.mtu)

            // Add addresses
            if (config.addresses.isEmpty()) {
                return Result.err(VpnError.ConfigurationFailed("At least one address must be specified"))
            }

            for (address in config.addresses) {
                try {
                    val parts = address.split("/")
                    if (parts.size != 2) {
                        return Result.err(VpnError.ConfigurationFailed("Invalid address format: $address (expected CIDR notation)"))
                    }
                    val ip = parts[0]
                    val prefixLength = parts[1].toIntOrNull()
                        ?: return Result.err(VpnError.ConfigurationFailed("Invalid prefix length in: $address"))

                    builder.addAddress(ip, prefixLength)
                } catch (e: Exception) {
                    return Result.err(VpnError.ConfigurationFailed("Failed to add address $address: ${e.message}", e))
                }
            }

            // Add dns
            for (dns in config.dnsServers) {
                try {
                    builder.addDnsServer(dns)
                    Log.i(TAG, "Added DNS server: $dns")
                } catch (e: Exception) {
                    return Result.err(VpnError.ConfigurationFailed("Failed to add DNS server $dns: ${e.message}", e))
                }
            }

            // Add routes
            for (route in config.routes) {
                try {
                    val parts = route.to.split("/")
                    if (parts.size != 2) {
                        return Result.err(VpnError.ConfigurationFailed("Invalid route CIDR format: ${route.to}"))
                    }
                    val ip = parts[0]
                    val prefixLength = parts[1].toIntOrNull()
                        ?: return Result.err(VpnError.ConfigurationFailed("Invalid prefix length in route: ${route.to}"))

                    builder.addRoute(ip, prefixLength)
                } catch (e: Exception) {
                    return Result.err(VpnError.ConfigurationFailed("Failed to add route ${route.to}: ${e.message}", e))
                }
            }

            // Establish the VPN
            val tunFd = builder.establish()
                ?: return Result.err(VpnError.ConfigurationFailed("Failed to establish VPN tunnel (establish() returned null)"))

            Log.i(TAG, "VPN tunnel established successfully")

            // Create and store the instance
            val instance = VpnInstance(tunFd)
            currentInstance = instance

            return Result.ok(instance)

        } catch (e: SecurityException) {
            Log.e(TAG, "Security exception while creating tunnel", e)
            return Result.err(VpnError.PermissionDenied)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create tunnel", e)
            return Result.err(VpnError.Failed("Failed to create VPN tunnel: ${e.message}", e))
        }
    }

    /**
     * Stop the current VPN instance if any.
     */
    fun stopTunnel() {
        currentInstance?.let { instance ->
            Log.i(TAG, "Stopping VPN tunnel")
            instance.notifyTermination(VpnInstance.TerminationReason.UserRequested)
            currentInstance = null
        }
        stopSelf()
    }

    /**
     * Get the currently active VPN instance, if any.
     */
    fun getCurrentInstance(): VpnInstance? = currentInstance

    override fun onDestroy() {
        super.onDestroy()
        Log.i(TAG, "VPN service destroyed")
        currentInstance?.notifyTermination(VpnInstance.TerminationReason.ServiceRevoked)
        currentInstance = null
    }

    companion object {
        private const val TAG = "KqtVpnService"
    }
}


