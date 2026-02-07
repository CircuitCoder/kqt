package plus.meow.kqt.crypto

/**
 * Security tiers for key provisioning and authentication.
 */
enum class SecurityTier {
    /**
     * No authentication required.
     * WARNING: VPN configs are still encrypted, but key is accessible without user authentication.
     */
    NONE,

    /**
     * Authentication valid for 5 minutes (300 seconds).
     * Allows both biometric and device credentials.
     * Allows new biometric enrollment.
     */
    TIMEOUT_5_MIN,

    /**
     * Authentication required for every use.
     * Allows both biometric and device credentials (password/PIN).
     * Allows new biometric enrollment.
     */
    EVERY_USE_FLEXIBLE,

    /**
     * Authentication required for every use.
     * Only accepts biometric authentication (no password/PIN fallback).
     * Key invalidated when new biometric is enrolled (maximum security).
     */
    EVERY_USE_BIOMETRIC_STRICT;

    /**
     * Get a human-readable name for this security tier.
     */
    fun getDisplayName(): String = when (this) {
        NONE -> "No Authentication"
        TIMEOUT_5_MIN -> "Authentication every 5 minutes"
        EVERY_USE_FLEXIBLE -> "Authentication every use (flexible)"
        EVERY_USE_BIOMETRIC_STRICT -> "Authentication every use (biometric only)"
    }

    /**
     * Get a description of this security tier.
     */
    fun getDescription(): String = when (this) {
        NONE -> "VPN configs are encrypted but accessible without authentication. Convenient but less secure."
        TIMEOUT_5_MIN -> "Authenticate once, valid for 5 minutes. Good balance of security and convenience."
        EVERY_USE_FLEXIBLE -> "Authenticate every time you access VPN configs. Accepts biometric or password/PIN. New biometric enrollments allowed."
        EVERY_USE_BIOMETRIC_STRICT -> "Authenticate every time with biometrics only. Key invalidated if new fingerprint/face is added. Maximum security."
    }

    /**
     * Check if this tier requires user authentication.
     */
    fun requiresAuthentication(): Boolean = this != NONE

    /**
     * Get the authentication timeout in seconds.
     * Returns -1 for no timeout (auth required every use).
     * Returns 0 for no authentication required.
     */
    fun getAuthTimeoutSeconds(): Int = when (this) {
        NONE -> 0
        TIMEOUT_5_MIN -> 300
        EVERY_USE_FLEXIBLE, EVERY_USE_BIOMETRIC_STRICT -> -1
    }

    /**
     * Check if this tier should invalidate key on new biometric enrollment.
     */
    fun shouldInvalidateOnEnrollment(): Boolean = when (this) {
        EVERY_USE_BIOMETRIC_STRICT -> true
        else -> false
    }

    /**
     * Check if this tier allows device credentials (password/PIN) as fallback.
     */
    fun allowsDeviceCredentials(): Boolean = when (this) {
        EVERY_USE_BIOMETRIC_STRICT -> false
        else -> true
    }
}

