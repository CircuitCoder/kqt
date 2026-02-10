package plus.meow.kqt.vpn

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.IBinder
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import plus.meow.kqt.utils.Result

/**
 * Manager for VPN operations.
 *
 * This class provides a high-level API for creating and managing VPN connections.
 * It handles service binding, permission requests, and VPN lifecycle management.
 *
 * Usage:
 * ```
 * val manager = VpnManager.getInstance(context)
 * manager.bind()
 * try {
 *     when (val result = manager.createVpn(config)) {
 *         is Result.Ok -> {
 *             val instance = result.value
 *             // Use instance.tunFd for the tunnel file descriptor
 *             // Monitor termination with instance.terminated.await()
 *         }
 *         is Result.Err -> {
 *             // Handle error
 *         }
 *     }
 * } finally {
 *     manager.unbind()
 * }
 * ```
 */
class VpnManager private constructor(
    private val context: Context
) {
    private var service: KqtVpnService? = null
    private var serviceConnection: ServiceConnection? = null
    private val bindDeferred = CompletableDeferred<Unit>()

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            Log.i(TAG, "VPN service connected")
            service = (binder as? KqtVpnService.LocalBinder)?.getService()
            bindDeferred.complete(Unit)
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            Log.i(TAG, "VPN service disconnected")
            service = null
        }
    }

    /**
     * Bind to the VPN service.
     * This must be called before creating VPN instances.
     */
    suspend fun bind() {
        withContext(Dispatchers.Main) {
            if (serviceConnection != null) {
                Log.w(TAG, "Service already bound or binding")
                return@withContext
            }

            val intent = Intent(context, KqtVpnService::class.java)
            val bound = context.bindService(
                intent,
                connection,
                Context.BIND_AUTO_CREATE
            )

            if (!bound) {
                Log.e(TAG, "Failed to bind to VPN service")
                throw IllegalStateException("Failed to bind to VPN service")
            }

            serviceConnection = connection

            // Wait for the service to be connected
            bindDeferred.await()
        }
    }

    /**
     * Unbind from the VPN service.
     * Should be called when the manager is no longer needed.
     */
    fun unbind() {
        serviceConnection?.let {
            context.unbindService(it)
            serviceConnection = null
        }
        service = null
    }

    /**
     * Check if VPN permission is granted.
     * If not granted, this returns an Intent that should be used to request permission.
     *
     * @return null if permission is granted, or an Intent to request permission
     */
    fun checkPermission(): Intent? {
        return VpnService.prepare(context)
    }

    /**
     * Create a VPN instance with the given configuration.
     *
     * This method will:
     * 1. Check VPN permissions (returns error if not granted)
     * 2. Stop any existing VPN instance
     * 3. Configure and start the new VPN
     * 4. Return a VpnInstance that can be used to monitor and control the VPN
     *
     * @param config The VPN configuration
     * @return Result with VpnInstance on success, or VpnError on failure
     */
    suspend fun createVpn(config: VpnConfig): Result<VpnInstance, VpnError> {
        return withContext(Dispatchers.Main) {
            // Check if service is bound
            val svc = service
                ?: return@withContext Result.err(VpnError.ServiceUnavailable)

            // Check permission
            val permissionIntent = checkPermission()
            if (permissionIntent != null) {
                Log.w(TAG, "VPN permission not granted")
                return@withContext Result.err(VpnError.PermissionDenied)
            }

            // Create the tunnel
            svc.createTunnel(config)
        }
    }

    /**
     * Stop the current VPN instance if any.
     */
    fun stopVpn() {
        service?.stopTunnel()
    }

    /**
     * Get the currently active VPN instance, if any.
     */
    fun getCurrentInstance(): VpnInstance? {
        return service?.getCurrentInstance()
    }

    /**
     * Request VPN permission from the user.
     * This should be called from an Activity when checkPermission() returns a non-null Intent.
     *
     * @param activity The activity to use for the permission request
     * @param requestCode The request code to use for the permission request
     */
    fun requestPermission(activity: Activity, requestCode: Int = REQUEST_VPN_PERMISSION) {
        val intent = checkPermission()
        if (intent != null) {
            activity.startActivityForResult(intent, requestCode)
        }
    }

    companion object {
        private const val TAG = "VpnManager"
        const val REQUEST_VPN_PERMISSION = 100

        @Volatile
        private var instance: VpnManager? = null

        /**
         * Get the singleton VpnManager instance.
         *
         * @param context Application or Activity context
         */
        fun getInstance(context: Context): VpnManager {
            return instance ?: synchronized(this) {
                instance ?: VpnManager(context.applicationContext).also { instance = it }
            }
        }
    }
}

/**
 * Example usage of VpnManager with Rust backend integration:
 *
 * Simple VPN creation:
 * ```
 * // 1. Get the VPN manager instance
 * val manager = VpnManager.getInstance(context)
 *
 * // 2. Bind to the service
 * manager.bind()
 *
 * // 3. Create VPN configuration
 * val config = VpnConfig(
 *     addresses = listOf("10.0.0.2/24"),
 *     routes = listOf(
 *         uniffi.kqt.SerializedRoute(to = "0.0.0.0/0", via = "10.0.0.1", metric = null)
 *     ),
 *     mtu = 1500
 * )
 *
 * // 4. Create VPN instance
 * when (val result = manager.createVpn(config)) {
 *     is Result.Ok -> {
 *         val instance = result.value
 *         val tunFd = instance.tunFd.fd
 *         // Use tunFd with backend...
 *     }
 *     is Result.Err -> {
 *         println("VPN creation failed: ${result.error}")
 *     }
 * }
 *
 * // 5. When done, unbind
 * manager.unbind()
 * ```
 *
 * With VpnBackendBridge (recommended):
 * ```
 * val manager = VpnManager.getInstance(context)
 * manager.bind()
 *
 * val bridge = VpnBackendBridge(manager)
 * val configString = "..." // Your config string
 *
 * when (val result = bridge.startVpnWithConfigString(configString)) {
 *     is Result.Ok -> println("VPN completed: ${result.value}")
 *     is Result.Err -> println("VPN failed: ${result.error}")
 * }
 *
 * manager.unbind()
 * ```
 */
