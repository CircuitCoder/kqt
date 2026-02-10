package plus.meow.kqt.vpn

import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import java.io.IOException

/**
 * Represents an active VPN connection instance.
 *
 * This class provides access to the VPN tunnel file descriptor and allows
 * monitoring and controlling the VPN connection lifecycle.
 *
 * @property tunFd The file descriptor of the VPN tunnel interface
 */
class VpnInstance internal constructor(
    val tunFd: ParcelFileDescriptor
) {
    private val terminationDeferred = CompletableDeferred<TerminationReason>()

    /**
     * A deferred that completes when the VPN is terminated.
     * Await this to be notified when the VPN stops.
     */
    val terminated: Deferred<TerminationReason> = terminationDeferred

    /**
     * Callback invoked when the VPN is terminated.
     * Set this before the VPN terminates to receive notification.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    var onTerminated: ((TerminationReason) -> Unit)? = null
        set(value) {
            field = value
            // If already terminated, invoke immediately
            if (terminationDeferred.isCompleted) {
                value?.invoke(terminationDeferred.getCompleted())
            }
        }

    /**
     * Whether this VPN instance has been terminated.
     */
    val isTerminated: Boolean
        get() = terminationDeferred.isCompleted

    /**
     * Request this VPN instance to stop.
     * This initiates the termination process.
     */
    fun stop() {
        if (!isTerminated) {
            notifyTermination(TerminationReason.UserRequested)
        }
    }

    /**
     * Internal method to notify that the VPN has terminated.
     */
    internal fun notifyTermination(reason: TerminationReason) {
        if (terminationDeferred.complete(reason)) {
            // Close the file descriptor
            try {
                tunFd.close()
            } catch (_: IOException) {
                // Ignore errors during cleanup
            }

            // Invoke callback if set
            onTerminated?.invoke(reason)
        }
    }

    /**
     * Reasons why a VPN connection was terminated.
     */
    sealed class TerminationReason {
        /**
         * User requested the VPN to stop.
         */
        object UserRequested : TerminationReason() {
            override fun toString() = "User requested stop"
        }

        /**
         * VPN was stopped because another VPN instance was created.
         */
        object ReplacedByAnother : TerminationReason() {
            override fun toString() = "Replaced by another VPN"
        }

        /**
         * VPN service was revoked by the system or user.
         */
        object ServiceRevoked : TerminationReason() {
            override fun toString() = "Service revoked by system"
        }

        /**
         * VPN encountered an error and had to stop.
         */
        data class Error(val message: String, val exception: Exception? = null) : TerminationReason() {
            override fun toString() = "Error: $message"
        }
    }
}



