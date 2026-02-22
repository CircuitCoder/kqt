package plus.meow.kqt.vpn

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.selects.select
import plus.meow.kqt.utils.Result
import uniffi.kqt.ParsedConfig

/**
 * Handle for a running VPN lifecycle.
 * Contains the VPN instance and a deferred job that completes when the VPN terminates.
 */
data class VpnLifecycleHandle(
    val vpnInstance: VpnInstance,
    val terminationJob: Deferred<VpnTerminationResult>
)

/**
 * Bridge between Android VPN service and Rust backend.
 *
 * This class provides integration between the VPN manager and the Rust backend
 * through the uniffi FFI bindings.
 */
class VpnBackendBridge(
    private val manager: VpnManager
) {
    companion object {
        private const val TAG = "VpnBackendBridge"

        /**
         * Singleton Runtime instance that persists for the app's lifetime.
         *
         * The Runtime is created once and reused for all VPN connections.
         * This is required by the backend and should remain alive as long as
         * the VpnService is running.
         */
        private var runtime: uniffi.kqt.Runtime? = null

        /**
         * Get or create the singleton Runtime instance.
         *
         * This method is thread-safe and ensures only one Runtime instance
         * is created for the entire application lifetime.
         */
        @Synchronized
        private fun getRuntime(): uniffi.kqt.Runtime {
            return runtime ?: uniffi.kqt.Runtime().also {
                runtime = it
                Log.i(TAG, "Created singleton Runtime instance")
            }
        }
    }

    /**
     * Construct a VpnConfig from a ParsedConfig.
     *
     * This extracts the IP addresses, routes, and MTU from the Rust backend's
     * configuration and creates an Android VpnConfig.
     *
     * @param parsedConfig The parsed configuration from the Rust backend
     * @return VpnConfig ready to be used with VpnManager
     */
    fun configFromParsed(parsedConfig: ParsedConfig): VpnConfig {
        // Get addresses from the parsed config
        val addresses = parsedConfig.address()

        // Get routes from the parsed config
        // SerializedRoute is used directly in VpnConfig
        val routes = parsedConfig.route()

        // Get MTU from the parsed config (it returns UShort? so we need to handle null)
        val mtu = parsedConfig.mtu()?.toInt() ?: 1500

        val dnsServers = parsedConfig.dns()

        return VpnConfig(
            addresses = addresses,
            dnsServers = dnsServers,
            routes = routes,
            mtu = mtu
        )
    }

    /**
     * Start the VPN with backend monitoring.
     *
     * This method:
     * 1. Creates a VPN instance with the provided configuration
     * 2. Starts the Rust backend with the tunnel file descriptor
     * 3. Launches a background job to monitor VPN/backend lifecycle
     * 4. Returns immediately with the VPN instance and termination job
     *
     * The caller can await the terminationJob to be notified when the VPN terminates.
     *
     * @param parsedConfig The parsed configuration from the Rust backend
     * @param scope The coroutine scope to launch the termination monitoring job in
     * @return Result with VpnLifecycleHandle on success, or VpnError on failure
     */
    suspend fun startVpnWithBackend(
        parsedConfig: ParsedConfig,
        scope: CoroutineScope
    ): Result<VpnLifecycleHandle, VpnError> = coroutineScope {
        try {
            // Step 1: Construct VpnConfig from ParsedConfig
            Log.i(TAG, "Constructing VPN configuration from parsed config")
            val vpnConfig = configFromParsed(parsedConfig)

            // Step 2: Start VPN instance
            Log.i(TAG, "Creating VPN instance")
            val vpnResult = manager.createVpn(vpnConfig)
            if (vpnResult is Result.Err) {
                Log.e(TAG, "Failed to create VPN instance: ${vpnResult.error}")
                return@coroutineScope Result.err(vpnResult.error)
            }

            val vpnInstance = (vpnResult as Result.Ok).value
            Log.i(TAG, "VPN instance created, fd=${vpnInstance.tunFd.fd}")

            // Step 3: Start the Rust backend with the tunnel file descriptor
            Log.i(TAG, "Starting Rust backend")
            val tunFd = vpnInstance.tunFd.fd

            // Get the singleton Runtime instance
            val runtime = getRuntime()

            // Convert MTU to UShort
            // TODO: actually gets device MTU
            val mtuUShort = vpnConfig.mtu.toUShort()

            val backendHandle = parsedConfig.start(runtime, tunFd, mtuUShort)
            Log.i(TAG, "Rust backend started successfully")

            // Step 4: Launch termination monitoring job
            Log.i(TAG, "Launching VPN lifecycle monitoring job")

            val terminationJob = scope.async(Dispatchers.IO) {
                try {
                    // Race both async tasks - when one completes, terminate the other
                    val result = select<VpnTerminationResult> {
                        // Branch 1: Backend completes first
                        async(Dispatchers.IO) {
                            try {
                                Log.i(TAG, "Waiting for backend to complete...")
                                backendHandle.wait()
                                Log.i(TAG, "Backend completed")

                                // Backend finished, terminate VPN if not already terminated
                                vpnInstance.notifyTermination(VpnInstance.TerminationReason.ServiceRevoked)

                                VpnTerminationResult.BackendTerminated
                            } catch (e: Exception) {
                                Log.e(TAG, "Backend error: ${e.message}", e)

                                // Backend failed, stop VPN
                                if (!vpnInstance.isTerminated) {
                                    Log.i(TAG, "Backend failed, stopping VPN")
                                    vpnInstance.stop()
                                }

                                VpnTerminationResult.BackendError(e.message ?: "Unknown error", e)
                            }
                        }.onAwait { it }

                        // Branch 2: VPN completes first
                        async(Dispatchers.IO) {
                            try {
                                Log.i(TAG, "Waiting for VPN to terminate...")
                                val terminationReason = vpnInstance.terminated.await()
                                Log.i(TAG, "VPN terminated: $terminationReason")

                                // VPN finished, stop backend
                                Log.i(TAG, "VPN terminated, stopping backend")
                                backendHandle.stop()

                                VpnTerminationResult.VpnTerminated(terminationReason)
                            } catch (e: Exception) {
                                Log.e(TAG, "VPN error: ${e.message}", e)

                                // VPN failed, stop backend
                                try {
                                    backendHandle.stop()
                                } catch (stopError: Exception) {
                                    Log.e(TAG, "Error stopping backend: ${stopError.message}", stopError)
                                }

                                VpnTerminationResult.VpnError(e.message ?: "Unknown error", e)
                            }
                        }.onAwait { it }
                    }

                    Log.i(TAG, "VPN lifecycle completed: $result")
                    result
                } catch (e: Exception) {
                    Log.e(TAG, "Unexpected error during VPN lifecycle monitoring: ${e.message}", e)
                    VpnTerminationResult.VpnError("Unexpected error: ${e.message}", e)
                }
            }

            // Return immediately with the VPN instance and termination job
            val handle = VpnLifecycleHandle(vpnInstance, terminationJob)
            Result.ok(handle)

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during VPN startup: ${e.message}", e)
            Result.err(VpnError.Failed("Unexpected error: ${e.message}", e))
        }
    }
}

/**
 * Result of VPN termination, indicating which component terminated and why.
 */
sealed class VpnTerminationResult {
    /**
     * The VPN instance terminated (user requested, replaced, revoked, etc.)
     */
    data class VpnTerminated(val reason: VpnInstance.TerminationReason) : VpnTerminationResult() {
        override fun toString() = "VPN terminated: $reason"
    }

    /**
     * The backend completed normally.
     */
    object BackendTerminated : VpnTerminationResult() {
        override fun toString() = "Backend terminated normally"
    }

    /**
     * The VPN encountered an error.
     */
    data class VpnError(val message: String, val exception: Exception? = null) : VpnTerminationResult() {
        override fun toString() = "VPN error: $message"
    }

    /**
     * The backend encountered an error.
     */
    data class BackendError(val message: String, val exception: Exception? = null) : VpnTerminationResult() {
        override fun toString() = "Backend error: $message"
    }
}
