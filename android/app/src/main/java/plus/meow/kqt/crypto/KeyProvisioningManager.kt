package plus.meow.kqt.crypto

import android.content.Context
import android.content.SharedPreferences

/**
 * Manages key provisioning state and security tier configuration.
 */
class KeyProvisioningManager(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences(
        PREFS_NAME,
        Context.MODE_PRIVATE
    )

    companion object {
        private const val PREFS_NAME = "key_provisioning"
        private const val KEY_IS_PROVISIONED = "is_provisioned"
        private const val KEY_SECURITY_TIER = "security_tier"
    }

    /**
     * Check if the master key has been provisioned.
     */
    fun isProvisioned(): Boolean {
        return prefs.getBoolean(KEY_IS_PROVISIONED, false)
    }

    /**
     * Mark the key as provisioned with the given security tier.
     */
    fun markAsProvisioned(securityTier: SecurityTier) {
        prefs.edit()
            .putBoolean(KEY_IS_PROVISIONED, true)
            .putString(KEY_SECURITY_TIER, securityTier.name)
            .apply()
    }

    /**
     * Get the configured security tier.
     * Returns null if not yet provisioned.
     */
    fun getSecurityTier(): SecurityTier? {
        val tierName = prefs.getString(KEY_SECURITY_TIER, null) ?: return null
        return try {
            SecurityTier.valueOf(tierName)
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    /**
     * Reset provisioning state (for testing or reprovisioning).
     * WARNING: Does not delete the actual keystore key!
     */
    fun reset() {
        prefs.edit()
            .clear()
            .apply()
    }
}

