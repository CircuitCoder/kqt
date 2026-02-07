package plus.meow.kqt

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.DisplayMetrics
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.TooltipCompat
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.launch
import plus.meow.kqt.crypto.CryptoManager
import plus.meow.kqt.repository.VpnConfigRepository
import plus.meow.kqt.storage.VpnConfigEntity
import plus.meow.kqt.utils.Result
import java.util.UUID

class EditVpnBottomSheet : BottomSheetDialogFragment() {

    private lateinit var entry: VpnConfigEntity
    private var onChanged: (() -> Unit)? = null
    private var onToggle: ((UUID, Boolean) -> Unit)? = null
    private var nameValidator: ((UUID, String) -> String?)? = null
    private lateinit var repository: VpnConfigRepository
    private lateinit var cryptoManager: CryptoManager

    private lateinit var nameInput: TextInputEditText
    private lateinit var toggleButton: MaterialButton
    private lateinit var saveButton: MaterialButton
    private lateinit var configText: TextView
    private lateinit var exportButton: MaterialButton

    private var draftName: String = ""
    private var isRunning: Boolean = false

    // State for configuration editing
    private var decryptedConfiguration: String? = null
    private var isConfigEdited: Boolean = false

    // Activity result launchers for export and import
    private val exportLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                exportConfigToUri(uri)
            }
        }
    }

    private val importLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                importConfigFromUri(uri)
            }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.sheet_edit_vpn, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        initializeViews(view)
        setupListeners()
        configureBottomSheet(view)
        loadEntry()
    }

    private fun initializeViews(view: View) {
        nameInput = view.findViewById(R.id.nameInput)
        toggleButton = view.findViewById(R.id.toggleIconButton)
        saveButton = view.findViewById(R.id.saveButton)
        configText = view.findViewById(R.id.configText)

        exportButton = view.findViewById(R.id.exportButton)
        val importButton = view.findViewById<MaterialButton>(R.id.importButton)
        val deleteButton = view.findViewById<MaterialButton>(R.id.deleteButton)

        exportButton.setOnClickListener {
            handleExport()
        }

        importButton.setOnClickListener {
            handleImport()
        }

        deleteButton.setOnClickListener {
            handleDelete()
        }
    }

    private fun loadEntry() {
        // Initialize UI from entity data
        draftName = entry.name
        nameInput.setText(draftName)
        toggleButton.isChecked = isRunning

        // Check if config exists (based on encryptedConfig field)
        val hasConfig = entry.encryptedConfig != null

        // Disable export and toggle buttons if no config
        exportButton.isEnabled = hasConfig
        toggleButton.isEnabled = hasConfig

        // Set tooltips for disabled buttons
        if (!hasConfig) {
            TooltipCompat.setTooltipText(exportButton, getString(R.string.no_config_tooltip))
            TooltipCompat.setTooltipText(toggleButton, getString(R.string.no_config_tooltip))
        }

        // Show placeholder for config
        updateConfigDisplay()
        updateSaveEnabled()
    }

    private fun setupListeners() {
        nameInput.doAfterTextChanged { text ->
            draftName = text?.toString()?.trim().orEmpty()
            validateName()
            updateSaveEnabled()
        }

        toggleButton.addOnCheckedChangeListener { _, checked ->
            onToggle?.invoke(entry.id, checked)
        }

        saveButton.setOnClickListener {
            if (saveButton.isEnabled) {
                performSave()
            }
        }
    }

    private fun validateName(): Boolean {
        nameInput.error = nameValidator?.invoke(entry.id, draftName)
        return nameInput.error == null
    }

    private fun performSave() {
        val trimmedName = draftName.trim()

        // Create updated entity based on what changed
        val updatedEntity = if (isConfigEdited) {
            // Use the "with configuration" update pathway
            // This requires biometric authentication
            val config = decryptedConfiguration ?: return

            val ret = entry.withNameAndConfig(trimmedName, config, cryptoManager)
            when (ret) {
                is Result.Err -> {
                    ret.toast(requireContext())
                    return
                }
                is Result.Ok -> ret.value
            }
        } else {
            // Only update the name (no authentication needed)
            entry.copy(name = trimmedName)
        }

        lifecycleScope.launch {
            val ret = repository.update(updatedEntity)
            if (ret is Result.Err) ret.toast(requireContext())
            dismiss()
        }
    }

    private fun updateSaveEnabled() {
        val trimmedName = draftName.trim()
        val hasChanged = trimmedName != entry.name
        val isValid = validateName()

        // Enable save button if name changed OR config is edited, and name is valid
        saveButton.isEnabled = (hasChanged || isConfigEdited) && isValid
    }

    private fun updateConfigDisplay() {
        if (decryptedConfiguration == null) {
            configText.setText(R.string.config_placeholder)
        } else {
            configText.text = decryptedConfiguration
        }
    }

    private fun configureBottomSheet(view: View) {
        (dialog as? BottomSheetDialog)?.setOnShowListener {
            val bottomSheet = dialog?.findViewById<View>(
                com.google.android.material.R.id.design_bottom_sheet
            )
            if (bottomSheet != null) {
                val behavior = BottomSheetBehavior.from(bottomSheet)
                val peekHeight = resources.getDimensionPixelSize(R.dimen.bottom_sheet_peek_height)
                behavior.peekHeight = peekHeight
                behavior.state = BottomSheetBehavior.STATE_COLLAPSED
                behavior.isFitToContents = true
                behavior.skipCollapsed = false

                // Set minimum height to screen height
                view.minimumHeight = getScreenHeight()
            }
        }
    }

    private fun handleExport() {
        val name = draftName.trim().ifEmpty { "config" }

        // Create intent to save file
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "text/plain"
            putExtra(Intent.EXTRA_TITLE, "$name.toml")
        }
        exportLauncher.launch(intent)
    }

    private fun exportConfigToUri(uri: Uri) {
        val config = when (val result = entry.decryptConfig(cryptoManager)) {
            is Result.Ok -> result.value
            is Result.Err -> {
                result.toast(requireContext())
                return
            }
        }

        // Check if config is null (no config stored)
        if (config == null) {
            Toast.makeText(requireContext(), "No configuration to export", Toast.LENGTH_SHORT).show()
            return
        }

        try {
            requireContext().contentResolver.openOutputStream(uri)?.use { outputStream ->
                outputStream.write(config.toByteArray())
            }
            Toast.makeText(requireContext(), "Configuration exported", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(requireContext(), "Failed to export: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun handleImport() {
        // Create intent to open file
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("text/plain", "text/*", "application/toml"))
        }
        importLauncher.launch(intent)
    }

    private fun importConfigFromUri(uri: Uri) {

        lifecycleScope.launch {
            try {
                val configContent = requireContext().contentResolver.openInputStream(uri)?.use { inputStream ->
                    inputStream.bufferedReader().readText()
                } ?: run {
                    Toast.makeText(requireContext(), "Failed to read file", Toast.LENGTH_SHORT).show()
                    return@launch
                }

                // Don't update database directly - store in decryptedConfiguration
                decryptedConfiguration = configContent
                isConfigEdited = true

                // Update UI
                updateConfigDisplay()
                updateSaveEnabled()

                // Enable buttons now that config exists
                exportButton.isEnabled = true
                toggleButton.isEnabled = true
                // Clear tooltips since buttons are now enabled
                TooltipCompat.setTooltipText(exportButton, null)
                TooltipCompat.setTooltipText(toggleButton, null)

                Toast.makeText(requireContext(), "Configuration imported", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(requireContext(), "Failed to import: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun handleDelete() {
        // Show confirmation dialog
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.delete_vpn_title)
            .setMessage(getString(R.string.delete_vpn_message, draftName))
            .setPositiveButton(R.string.delete) { _, _ ->
                lifecycleScope.launch {
                    when (val result = repository.delete(entry.id)) {
                        is Result.Ok -> {
                            // Success - notify parent and dismiss
                            onChanged?.invoke()
                            dismiss()
                        }
                        is Result.Err -> {
                            result.toast(requireContext())
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun getScreenHeight(): Int {
        return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            val windowMetrics = requireActivity().windowManager.currentWindowMetrics
            windowMetrics.bounds.height()
        } else {
            @Suppress("DEPRECATION")
            val displayMetrics = DisplayMetrics()
            @Suppress("DEPRECATION")
            requireActivity().windowManager.defaultDisplay.getMetrics(displayMetrics)
            displayMetrics.heightPixels
        }
    }

    companion object {
        fun newInstance(
            entity: VpnConfigEntity,
            isRunning: Boolean,
            repository: VpnConfigRepository,
            cryptoManager: CryptoManager,
            nameValidator: (UUID, String) -> String?,
            onChanged: () -> Unit,
            onToggle: (UUID, Boolean) -> Unit
        ): EditVpnBottomSheet {
            return EditVpnBottomSheet().apply {
                this.entry = entity
                this.isRunning = isRunning
                this.repository = repository
                this.cryptoManager = cryptoManager
                this.nameValidator = nameValidator
                this.onChanged = onChanged
                this.onToggle = onToggle
            }
        }
    }
}

