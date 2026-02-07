package plus.meow.kqt

import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textview.MaterialTextView
import plus.meow.kqt.crypto.BiometricAuthManager
import plus.meow.kqt.crypto.CryptoManager
import plus.meow.kqt.crypto.KeyProvisioningManager
import plus.meow.kqt.crypto.KeystoreCapabilities
import plus.meow.kqt.crypto.SecurityTier

/**
 * Activity for provisioning the master encryption key on first launch.
 */
class KeyProvisioningActivity : AppCompatActivity() {

    private lateinit var securityTierRadioGroup: RadioGroup
    private lateinit var radioNone: RadioButton
    private lateinit var radioTimeout: RadioButton
    private lateinit var radioEveryUseFlexible: RadioButton
    private lateinit var radioEveryUseBiometric: RadioButton
    private lateinit var descriptionText: MaterialTextView
    private lateinit var featuresList: LinearLayout
    private lateinit var capabilitiesList: LinearLayout
    private lateinit var capabilitiesDivider: View
    private lateinit var capabilitiesHint: MaterialTextView
    private lateinit var continueButton: MaterialButton

    private lateinit var provisioningManager: KeyProvisioningManager
    private lateinit var cryptoManager: CryptoManager
    private lateinit var biometricAuthManager: BiometricAuthManager
    private lateinit var keystoreCapabilities: KeystoreCapabilities

    private var selectedSecurityTier: SecurityTier = SecurityTier.TIMEOUT_5_MIN

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_key_provisioning)

        // Initialize managers
        provisioningManager = KeyProvisioningManager(this)
        cryptoManager = CryptoManager()
        biometricAuthManager = BiometricAuthManager(this)
        keystoreCapabilities = KeystoreCapabilities(this)

        // Bind views
        securityTierRadioGroup = findViewById(R.id.securityTierRadioGroup)
        radioNone = findViewById(R.id.radioNone)
        radioTimeout = findViewById(R.id.radioTimeout)
        radioEveryUseFlexible = findViewById(R.id.radioEveryUseFlexible)
        radioEveryUseBiometric = findViewById(R.id.radioEveryUseBiometric)
        descriptionText = findViewById(R.id.descriptionText)
        featuresList = findViewById(R.id.featuresList)
        capabilitiesList = findViewById(R.id.capabilitiesList)
        capabilitiesDivider = findViewById(R.id.capabilitiesDivider)
        capabilitiesHint = findViewById(R.id.capabilitiesHint)
        continueButton = findViewById(R.id.continueButton)

        // Set up listeners
        setupRadioGroupListener()
        continueButton.setOnClickListener { onContinueClicked() }

        // Update description for default selection
        updateDescription(selectedSecurityTier)


        // Check if biometric is available and disable strict biometric option if not
        if (!isBiometricAvailable()) {
            radioEveryUseBiometric.isEnabled = false
            radioEveryUseBiometric.alpha = 0.5f
        }
    }

    private fun setupRadioGroupListener() {
        securityTierRadioGroup.setOnCheckedChangeListener { _, checkedId ->
            selectedSecurityTier = when (checkedId) {
                R.id.radioNone -> SecurityTier.NONE
                R.id.radioTimeout -> SecurityTier.TIMEOUT_5_MIN
                R.id.radioEveryUseFlexible -> SecurityTier.EVERY_USE_FLEXIBLE
                R.id.radioEveryUseBiometric -> SecurityTier.EVERY_USE_BIOMETRIC_STRICT
                else -> SecurityTier.TIMEOUT_5_MIN
            }
            updateDescription(selectedSecurityTier)
        }
    }

    private fun updateDescription(tier: SecurityTier) {
        descriptionText.text = tier.getDescription()
        updateFeaturesList(tier)
        displayHardwareCapabilities(tier)
    }

    private fun updateFeaturesList(tier: SecurityTier) {
        featuresList.removeAllViews()

        val features = when (tier) {
            SecurityTier.NONE -> listOf(
                Feature("No authentication required", true),
                Feature("Convenient access", true),
                Feature("Less secure", false),
                Feature("Not recommended for sensitive data", false)
            )
            SecurityTier.TIMEOUT_5_MIN -> listOf(
                Feature("Authenticate once every 5 minutes", true),
                Feature("Biometric or password/PIN accepted", true),
                Feature("Good balance of security and convenience", true),
                Feature("New biometric enrollments allowed", true)
            )
            SecurityTier.EVERY_USE_FLEXIBLE -> listOf(
                Feature("Authenticate every time", true),
                Feature("Biometric or password/PIN accepted", true),
                Feature("High security", true),
                Feature("New biometric enrollments allowed", true)
            )
            SecurityTier.EVERY_USE_BIOMETRIC_STRICT -> listOf(
                Feature("Authenticate every time", true),
                Feature("Biometric only (no password fallback)", true),
                Feature("Maximum security", true),
                Feature("Key invalidated on new fingerprint enrollment", true)
            )
        }

        features.forEach { feature ->
            val featureView = createFeatureView(feature)
            featuresList.addView(featureView)
        }
    }

    private fun createFeatureView(feature: Feature): View {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = 8
            }
        }

        val icon = ImageView(this).apply {
            layoutParams = LinearLayout.LayoutParams(16.dpToPx(), 16.dpToPx()).apply {
                marginEnd = 8.dpToPx()
                topMargin = 2.dpToPx()
            }
            setImageResource(if (feature.isPositive) R.drawable.ic_check else R.drawable.ic_close)
            setColorFilter(
                ContextCompat.getColor(
                    context,
                    if (feature.isPositive) android.R.color.holo_green_dark else android.R.color.holo_red_dark
                )
            )
        }

        val text = MaterialTextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                0,
                LinearLayout.LayoutParams.WRAP_CONTENT,
                1f
            )
            this.text = feature.text
            textSize = 12f
            // Use attribute color for better theming
            val typedValue = android.util.TypedValue()
            context.theme.resolveAttribute(
                com.google.android.material.R.attr.colorOnSecondaryContainer,
                typedValue,
                true
            )
            setTextColor(typedValue.data)
        }

        layout.addView(icon)
        layout.addView(text)

        return layout
    }

    private fun displayHardwareCapabilities(tier: SecurityTier) {
        val capabilities = keystoreCapabilities.getCapabilities()

        capabilitiesList.removeAllViews()

        // Determine which features are relevant for this security tier
        val relevantFeatures = mutableListOf<Pair<String, Boolean>>()

        when (tier) {
            SecurityTier.NONE -> {
                // For no authentication, only show encryption
                relevantFeatures.add("AES-256-GCM Encryption" to true)
                relevantFeatures.add("Hardware-backed Keystore" to capabilities.hardwareBackedKeystore)
            }
            SecurityTier.TIMEOUT_5_MIN, SecurityTier.EVERY_USE_FLEXIBLE -> {
                // For flexible auth modes, show all features
                relevantFeatures.add("AES-256-GCM Encryption" to true)
                relevantFeatures.add("Hardware-backed Keystore" to capabilities.hardwareBackedKeystore)
                if (capabilities.strongBox) {
                    relevantFeatures.add("StrongBox Secure Element" to true)
                }
                relevantFeatures.add("Biometric Authentication" to capabilities.biometric)
            }
            SecurityTier.EVERY_USE_BIOMETRIC_STRICT -> {
                // For strict biometric, emphasize biometric and StrongBox
                relevantFeatures.add("AES-256-GCM Encryption" to true)
                relevantFeatures.add("Hardware-backed Keystore" to capabilities.hardwareBackedKeystore)
                if (capabilities.strongBox) {
                    relevantFeatures.add("StrongBox Secure Element" to true)
                }
                relevantFeatures.add("Biometric Authentication" to capabilities.biometric)
            }
        }

        // Show/hide the capabilities section based on whether we have features to show
        if (relevantFeatures.isNotEmpty()) {
            capabilitiesDivider.visibility = View.VISIBLE
            capabilitiesHint.visibility = View.VISIBLE

            relevantFeatures.forEach { (name, isSupported) ->
                capabilitiesList.addView(createCapabilityView(name, isSupported))
            }
        } else {
            capabilitiesDivider.visibility = View.GONE
            capabilitiesHint.visibility = View.GONE
        }
    }

    private fun createCapabilityView(name: String, isSupported: Boolean): View {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = 6.dpToPx()
            }
        }

        val icon = ImageView(this).apply {
            layoutParams = LinearLayout.LayoutParams(16.dpToPx(), 16.dpToPx()).apply {
                marginEnd = 8.dpToPx()
                topMargin = 2.dpToPx()
            }
            setImageResource(if (isSupported) R.drawable.ic_check else R.drawable.ic_close)
            setColorFilter(
                ContextCompat.getColor(
                    context,
                    if (isSupported) android.R.color.holo_green_dark else android.R.color.darker_gray
                )
            )
        }

        val text = MaterialTextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                0,
                LinearLayout.LayoutParams.WRAP_CONTENT,
                1f
            )
            this.text = name
            textSize = 12f
            // Use colorOnSecondaryContainer to match the description card
            val typedValue = android.util.TypedValue()
            context.theme.resolveAttribute(
                com.google.android.material.R.attr.colorOnSecondaryContainer,
                typedValue,
                true
            )
            setTextColor(typedValue.data)
            alpha = if (isSupported) 0.8f else 0.5f
        }

        layout.addView(icon)
        layout.addView(text)

        return layout
    }

    private fun isBiometricAvailable(): Boolean {
        return biometricAuthManager.isBiometricAvailable()
    }

    private fun onContinueClicked() {
        // Show warning for NONE tier
        if (selectedSecurityTier == SecurityTier.NONE) {
            MaterialAlertDialogBuilder(this)
                .setTitle("Warning")
                .setMessage("You've chosen to disable authentication. Your VPN configs will be encrypted but accessible without biometric/password authentication. This is less secure.\n\nAre you sure you want to continue?")
                .setPositiveButton("Continue") { _, _ ->
                    provisionKey()
                }
                .setNegativeButton("Cancel", null)
                .show()
            return
        }

        // For biometric-strict mode, check if biometric is available
        if (selectedSecurityTier == SecurityTier.EVERY_USE_BIOMETRIC_STRICT && !isBiometricAvailable()) {
            Snackbar.make(
                continueButton,
                "Biometric authentication is not available on this device",
                Snackbar.LENGTH_LONG
            ).show()
            return
        }

        // For other tiers that require auth, show a test authentication
        if (selectedSecurityTier.requiresAuthentication()) {
            showTestAuthentication()
        } else {
            provisionKey()
        }
    }

    private fun showTestAuthentication() {
        biometricAuthManager.authenticate(
            title = "Test Authentication",
            subtitle = "Verify that authentication works",
            description = "This is a one-time test to ensure your chosen security method works properly."
        ) { result ->
            when (result) {
                is BiometricAuthManager.AuthResult.Success -> {
                    provisionKey()
                }
                is BiometricAuthManager.AuthResult.Error -> {
                    Snackbar.make(
                        continueButton,
                        "Authentication error: ${result.errorMessage}",
                        Snackbar.LENGTH_LONG
                    ).show()
                }
                is BiometricAuthManager.AuthResult.Failed -> {
                    Snackbar.make(
                        continueButton,
                        "Authentication failed. Please try again.",
                        Snackbar.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }

    private fun provisionKey() {
        try {
            // Provision the master key with the selected security tier
            cryptoManager.provisionMasterKey(selectedSecurityTier)

            // Mark as provisioned in preferences
            provisioningManager.markAsProvisioned(selectedSecurityTier)

            // Show success message
            Snackbar.make(
                continueButton,
                "Encryption key provisioned successfully!",
                Snackbar.LENGTH_SHORT
            ).show()

            // Finish and proceed to main activity
            finish()
        } catch (e: Exception) {
            // Handle provisioning error
            MaterialAlertDialogBuilder(this)
                .setTitle("Provisioning Failed")
                .setMessage("Failed to provision encryption key: ${e.message}\n\nPlease try again.")
                .setPositiveButton("OK", null)
                .show()
        }
    }

    private fun Int.dpToPx(): Int {
        return (this * resources.displayMetrics.density).toInt()
    }

    private data class Feature(val text: String, val isPositive: Boolean)
}


