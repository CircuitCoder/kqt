package plus.meow.kqt.vpn

/**
 * Error types that can occur during VPN operations.
 */
sealed class VpnError {
    /**
     * VPN permission was not granted by the user.
     */
    object PermissionDenied : VpnError() {
        override fun toString() = "VPN permission denied by user"
    }

    /**
     * Another VPN is already active.
     */
    object AlreadyActive : VpnError() {
        override fun toString() = "Another VPN is already active"
    }

    /**
     * VPN service is not available or not bound.
     */
    object ServiceUnavailable : VpnError() {
        override fun toString() = "VPN service is not available"
    }

    /**
     * Failed to configure or start the VPN.
     */
    data class ConfigurationFailed(val message: String, val exception: Exception? = null) : VpnError() {
        override fun toString() = "VPN configuration failed: $message"
    }

    /**
     * Generic VPN operation failure.
     */
    data class Failed(val message: String, val exception: Exception? = null) : VpnError() {
        override fun toString() = "VPN error: $message"
    }
}

