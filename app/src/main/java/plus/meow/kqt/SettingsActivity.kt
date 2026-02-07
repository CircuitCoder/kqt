package plus.meow.kqt

import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import plus.meow.kqt.crypto.CryptoManager
import plus.meow.kqt.crypto.KeyProvisioningManager
import plus.meow.kqt.storage.VpnConfigDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.system.exitProcess

/**
 * Settings activity for app configuration and data management.
 */
class SettingsActivity : AppCompatActivity() {

    private lateinit var toolbar: MaterialToolbar
    private lateinit var resetStorageCard: MaterialCardView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        // Set up toolbar
        toolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener {
            finish()
        }

        // Bind views
        resetStorageCard = findViewById(R.id.resetStorageCard)

        // Set up click listeners
        resetStorageCard.setOnClickListener {
            showResetStorageDialog()
        }
    }

    private fun showResetStorageDialog() {
        // Create styled message with bold and red "permanently delete"
        val message = "This will permanently delete:\n\n" +
                "GÇó All VPN configurations\n" +
                "GÇó All encryption keys\n" +
                "GÇó All app settings\n\n" +
                "This action cannot be undone. The app will close after reset."

        val spannableMessage = SpannableString(message)

        // Find "permanently delete" and make it bold and red
        val startIndex = message.indexOf("permanently delete")
        if (startIndex != -1) {
            val endIndex = startIndex + "permanently delete".length

            // Apply bold style
            spannableMessage.setSpan(
                StyleSpan(Typeface.BOLD),
                startIndex,
                endIndex,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )

            // Apply red color (using error color from theme)
            val errorColor = ContextCompat.getColor(this, com.google.android.material.R.color.design_default_color_error)
            spannableMessage.setSpan(
                ForegroundColorSpan(errorColor),
                startIndex,
                endIndex,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }

        // Create icon drawable - no tint needed, uses default foreground color
        val icon = ContextCompat.getDrawable(this, R.drawable.ic_delete)

        MaterialAlertDialogBuilder(this)
            .setTitle("Reset Storage?")
            .setMessage(spannableMessage)
            .setIcon(icon)
            .setPositiveButton("Reset") { _, _ ->
                performResetStorage()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun performResetStorage() {
        // Show progress dialog
        val progressDialog = MaterialAlertDialogBuilder(this)
            .setTitle("Resetting Storage")
            .setMessage("Please wait...")
            .setCancelable(false)
            .create()

        progressDialog.show()

        // Perform reset in background
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // 1. Delete all VPN configurations from database
                val database = VpnConfigDatabase.getInstance(this@SettingsActivity)
                database.vpnConfigDao().deleteAll()

                // 2. Reset provisioning state first (before deleting key)
                val provisioningManager = KeyProvisioningManager(this@SettingsActivity)

                // 3. Delete encryption keys from keystore (needs activity context)
                withContext(Dispatchers.Main) {
                    val cryptoManager = CryptoManager(this@SettingsActivity, provisioningManager)
                    cryptoManager.deleteMasterKey()
                }

                provisioningManager.reset()

                // 4. Clear database instance
                database.close()
                VpnConfigDatabase.clearInstance()

                // Switch to main thread to close app
                withContext(Dispatchers.Main) {
                    progressDialog.dismiss()

                    // Show completion message
                    MaterialAlertDialogBuilder(this@SettingsActivity)
                        .setTitle("Storage Reset Complete")
                        .setMessage("All data has been deleted. The app will now close.")
                        .setCancelable(false)
                        .setPositiveButton("OK") { _, _ ->
                            // Terminate the app
                            finishAffinity()
                            exitProcess(0)
                        }
                        .show()
                }
            } catch (e: Exception) {
                // Handle error
                withContext(Dispatchers.Main) {
                    progressDialog.dismiss()

                    MaterialAlertDialogBuilder(this@SettingsActivity)
                        .setTitle("Reset Failed - Inconsistent State")
                        .setMessage(
                            "Failed to reset storage: ${e.message}\n\n" +
                            "GÜán+Å WARNING: App data may be in an inconsistent state.\n\n" +
                            "To fix this:\n" +
                            "1. Force stop this app\n" +
                            "2. Clear app storage manually\n" +
                            "3. Restart the app\n\n" +
                            "Tap 'Open Settings' to go to app info screen."
                        )
                        .setIcon(R.drawable.ic_info)
                        .setPositiveButton("Open Settings") { _, _ ->
                            // Open app info settings screen
                            try {
                                val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                                intent.data = Uri.fromParts("package", packageName, null)
                                startActivity(intent)
                            } catch (_: Exception) {
                                // Fallback to general app settings if specific intent fails
                                val intent = Intent(Settings.ACTION_SETTINGS)
                                startActivity(intent)
                            }
                        }
                        .setNegativeButton("Cancel", null)
                        .setCancelable(false)
                        .show()
                }
            }
        }
    }
}

