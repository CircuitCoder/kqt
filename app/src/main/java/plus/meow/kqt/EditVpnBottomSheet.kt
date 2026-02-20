package plus.meow.kqt

import android.animation.ArgbEvaluator
import android.animation.ValueAnimator
import android.app.Activity
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.util.DisplayMetrics
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.TooltipCompat
import androidx.core.graphics.ColorUtils
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import io.github.rosemoe.sora.widget.CodeEditor
import io.github.rosemoe.sora.widget.schemes.EditorColorScheme.WHOLE_BACKGROUND
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import plus.meow.kqt.crypto.CryptoManager
import plus.meow.kqt.editor.TomlLanguageFactory
import plus.meow.kqt.repository.VpnConfigRepository
import plus.meow.kqt.storage.VpnConfigEntity
import plus.meow.kqt.utils.Result
import plus.meow.kqt.vpn.VpnState
import plus.meow.kqt.vpn.VpnStateManager
import kotlin.math.absoluteValue

/**
 * Represents the state of the toggle button combining VPN running state and pending changes
 */
private enum class ButtonState {
    IDLE,           // VPN off, no pending changes
    RUNNING,        // VPN on, no pending changes
    PENDING_SAVE    // Has pending changes (VPN can be on or off)
}

/**
 * Complete visual state for the button including colors, icon, and enabled state
 */
private data class ButtonVisualState(
    val state: ButtonState,
    val enabled: Boolean,
    val bg: Int,
    val fg: Int,
    val icon: Int
)

class EditVpnBottomSheet : BottomSheetDialogFragment() {

    private lateinit var entityId: kotlin.uuid.Uuid
    private lateinit var entryFlow: MutableStateFlow<VpnConfigEntity>
    private var onChanged: (() -> Unit)? = null
    private var onToggle: ((Boolean) -> Unit)? = null
    private lateinit var repository: VpnConfigRepository
    private lateinit var cryptoManager: CryptoManager
    private lateinit var vpnStateManager: VpnStateManager

    private lateinit var nameInput: TextInputEditText
    private lateinit var toggleButton: MaterialButton
    private lateinit var codeEditor: CodeEditor
    private lateinit var codeEditorWrapper: ViewGroup
    private lateinit var decryptPlaceholder: LinearLayout
    private lateinit var addConfigPlaceholder: LinearLayout
    private lateinit var exportButton: MaterialButton

    // State for configuration editing
    private var decryptedConfiguration: String? = null

    // State flows - source of truth
    private val draftNameFlow = MutableStateFlow("")
    private val isConfigEditedFlow = MutableStateFlow(false)

    // Derived validation error flow
    private lateinit var validationErrorFlow: kotlinx.coroutines.flow.Flow<String?>

    // Derived button visual state flow - single source of truth for button appearance
    private lateinit var buttonVisualStateFlow: kotlinx.coroutines.flow.Flow<ButtonVisualState>

    // Current button state animator
    private var currentAnimator: ValueAnimator? = null

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

    override fun onStart() {
        super.onStart()

        // Configure bottom sheet behavior after view is attached
        val dialog = dialog as? BottomSheetDialog
        val bottomSheet = dialog?.findViewById<View>(
            com.google.android.material.R.id.design_bottom_sheet
        )

        if (bottomSheet != null) {
            val screenHeight = getScreenHeight()
            val peekHeight = resources.getDimensionPixelSize(R.dimen.bottom_sheet_peek_height)

            // Force bottom sheet to full screen height
            val layoutParams = bottomSheet.layoutParams
            layoutParams.height = screenHeight
            bottomSheet.layoutParams = layoutParams

            val behavior = BottomSheetBehavior.from(bottomSheet)
            behavior.isFitToContents = false
            behavior.skipCollapsed = false
            behavior.peekHeight = peekHeight
            behavior.expandedOffset = 0
            behavior.maxHeight = screenHeight

            // Important: Allow the behavior to settle before setting state
            bottomSheet.post {
                behavior.state = BottomSheetBehavior.STATE_COLLAPSED
            }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Load entity from repository and initialize entryFlow
        lifecycleScope.launch {
            val entity = repository.listAll().find { it.id == entityId }
            if (entity == null) {
                // Entity not found, dismiss the sheet
                Toast.makeText(requireContext(), "VPN configuration not found", Toast.LENGTH_SHORT).show()
                dismiss()
                return@launch
            }

            // Initialize entryFlow
            entryFlow = MutableStateFlow(entity)

            // Now initialize the rest of the UI
            initializeViews(view)
            setupListeners()
            setupButtonStateObservation()
            loadEntry()
        }
    }

    private fun initializeViews(view: View) {
        nameInput = view.findViewById(R.id.nameInput)
        toggleButton = view.findViewById(R.id.toggleIconButton)
        codeEditor = view.findViewById(R.id.codeEditor)
        codeEditorWrapper = view.findViewById(R.id.codeEditorWrapper)
        decryptPlaceholder = view.findViewById(R.id.decryptPlaceholder)
        addConfigPlaceholder = view.findViewById(R.id.addConfigPlaceholder)

        exportButton = view.findViewById(R.id.exportButton)
        val importButton = view.findViewById<MaterialButton>(R.id.importButton)
        val deleteButton = view.findViewById<MaterialButton>(R.id.deleteButton)

        // Configure code editor
        configureCodeEditor()

        // Setup code editor text change listener
        codeEditor.subscribeEvent(io.github.rosemoe.sora.event.ContentChangeEvent::class.java) { _, _ ->
            if (decryptedConfiguration == codeEditor.text.toString()) {
                // Unchanged, initial update
                return@subscribeEvent
            }
            decryptedConfiguration = codeEditor.text.toString()
            isConfigEditedFlow.value = true
        }

        // Prevent bottom sheet drag when touching the editor
        setupEditorTouchBehavior()

        // Setup decrypt placeholder click listener
        decryptPlaceholder.setOnClickListener {
            handleDecryptConfig()
        }

        // Setup add config placeholder click listener
        addConfigPlaceholder.setOnClickListener {
            handleAddExampleConfig()
        }

        exportButton.setOnClickListener {
            handleExport()
        }

        importButton.setOnClickListener {
            handleImport()
        }

        deleteButton.setOnClickListener {
            handleDelete()
        }

        // Setup button state observation
        setupButtonStateObservation()
    }

    private fun configureCodeEditor() {
        // Initialize TextMate TOML language support
        TomlLanguageFactory.initialize(requireContext())

        // Disable line numbers
        codeEditor.isLineNumberEnabled = false

        // Set font size smaller but keep line height
        val textSizeSp = 11f  // Smaller than default (usually 14sp)
        codeEditor.setTextSize(textSizeSp)
        codeEditor.typefaceText = Typeface.MONOSPACE

        // Set line height to match original spacing
        codeEditor.setLineSpacing(2f, 1.2f)
        codeEditor.setHighlightCurrentLine(false)

        // Enable word wrap and disable horizontal scrolling
        codeEditor.isWordwrap = true

        // Configure theme based on system dark mode
        val isDarkMode = (resources.configuration.uiMode and
                android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
                android.content.res.Configuration.UI_MODE_NIGHT_YES

        // Set TOML language with appropriate theme (One Dark or One Light)
        codeEditor.colorScheme = TomlLanguageFactory.createColorScheme(isDarkMode)
        codeEditor.setEditorLanguage(TomlLanguageFactory.createLanguage())

        // Apply padding via wrapper by setting background color and padding
        // Get background color from the color scheme
        val backgroundColor = codeEditor.colorScheme.getColor(
            WHOLE_BACKGROUND
        )
        // Set wrapper background to match editor background
        codeEditorWrapper.setBackgroundColor(backgroundColor)

        // Enable hardware acceleration for better performance
        codeEditor.isHardwareAcceleratedDrawAllowed = true
    }

    @Suppress("ClickableViewAccessibility")
    private fun setupEditorTouchBehavior() {
        // Intercept touch events on the editor wrapper to prevent bottom sheet drag
        codeEditorWrapper.setOnTouchListener { view, event ->
            // When user touches the editor area, prevent parent from intercepting
            when (event.action) {
                android.view.MotionEvent.ACTION_DOWN -> {
                    // Disable parent interception when touch starts
                    view.parent?.requestDisallowInterceptTouchEvent(true)
                }
            }
            // Return false to let the editor handle the touch normally
            false
        }

        // Also set on the editor itself for extra safety
        codeEditor.setOnTouchListener { view, event ->
            when (event.action) {
                android.view.MotionEvent.ACTION_DOWN -> {
                    view.parent?.parent?.requestDisallowInterceptTouchEvent(true)
                }
            }
            false
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun setupButtonStateObservation() {
        // Create validation error flow
        validationErrorFlow = draftNameFlow.mapLatest { name ->
            validateVpnName(name)
        }

        // Observe validation error and update UI
        validationErrorFlow.onEach { error ->
            nameInput.error = error
        }.launchIn(lifecycleScope)

        // Create comprehensive button visual state flow - single source of truth
        buttonVisualStateFlow = combine(
            vpnStateManager.observe(entityId),
            entryFlow,
            draftNameFlow,
            validationErrorFlow,
            isConfigEditedFlow
        ) { vpnState, entry, draftName, validationError, isConfigEdited ->
            val isRunning = vpnState !is VpnState.Disconnected
            val trimmedName = draftName.trim()
            val nameChanged = trimmedName != entry.name
            val hasPendingChanges = nameChanged || isConfigEdited
            val hasConfig = entry.encryptedConfig != null || decryptedConfiguration != null

            // Determine button state
            val buttonState = when {
                hasPendingChanges -> ButtonState.PENDING_SAVE
                isRunning -> ButtonState.RUNNING
                else -> ButtonState.IDLE
            }

            // Determine enabled state
            val enabled = when (buttonState) {
                ButtonState.PENDING_SAVE -> validationError == null // Only enable save if validation passes
                else -> validationError == null && hasConfig
            }

            // Get theme colors
            val context = requireContext()
            val typedValue = android.util.TypedValue()
            val theme = context.theme

            fun resolveColor(attr: Int): Int {
                theme.resolveAttribute(attr, typedValue, true)
                return typedValue.data
            }

            val icon = when (buttonState) {
                ButtonState.IDLE -> R.drawable.ic_play
                ButtonState.RUNNING -> R.drawable.ic_stop
                ButtonState.PENDING_SAVE -> R.drawable.ic_save
            }

            // Determine colors and icon based on state and enabled status
            val (bg, fg) = if (!enabled) {
                // Disabled state: grey background
                Pair(
                    resolveColor(com.google.android.material.R.attr.colorSurfaceVariant),
                    resolveColor(com.google.android.material.R.attr.colorOnSurfaceVariant),
                )
            } else {
                // Enabled state: state-specific colors
                when (buttonState) {
                    ButtonState.IDLE -> Pair(
                        resolveColor(android.R.attr.colorPrimary),
                        resolveColor(com.google.android.material.R.attr.colorOnPrimary),
                    )
                    ButtonState.RUNNING -> Pair(
                        resolveColor(android.R.attr.colorPrimary),
                        resolveColor(com.google.android.material.R.attr.colorOnPrimary),
                    )
                    ButtonState.PENDING_SAVE -> Pair(
                        context.getColor(android.R.color.holo_green_dark),
                        context.getColor(android.R.color.white),
                    )
                }
            }

            ButtonVisualState(buttonState, enabled, bg, fg, icon)
        }

        // Observe the button visual state and animate transitions
        buttonVisualStateFlow.onEach { visualState ->
            animateToVisualState(visualState)
        }.launchIn(lifecycleScope)
    }

    /**
     * Validate VPN name against business rules
     * Returns error message if invalid, null if valid
     */
    private suspend fun validateVpnName(name: String): String? {
        val context = requireContext()
        return when {
            name != name.trim() -> context.getString(R.string.vpn_name_empty) // Untrimmed
            name.isEmpty() -> context.getString(R.string.vpn_name_empty)
            name.length > 50 -> context.getString(R.string.vpn_name_too_long)
            else -> {
                // Check for name conflicts in repository
                val allConfigs = repository.listAll()
                if (allConfigs.any { it.id != entityId && it.name == name }) {
                    context.getString(R.string.vpn_name_conflict)
                } else {
                    null
                }
            }
        }
    }

    private fun loadEntry() {
        val entry = entryFlow.value

        // Initialize UI from entity data
        draftNameFlow.value = entry.name
        nameInput.setText(entry.name)

        // Initialize button icon tag for animation tracking
        toggleButton.tag = R.drawable.ic_play

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
    }

    private fun setupListeners() {
        nameInput.doAfterTextChanged { text ->
            val newName = text?.toString()?.trim().orEmpty()
            draftNameFlow.value = newName
        }

        toggleButton.setOnClickListener {
            handleToggleButtonClick()
        }
    }


    private fun handleToggleButtonClick() {
        lifecycleScope.launch {
            // Get current button state from the flow
            val currentVisualState = buttonVisualStateFlow.first()

            when (currentVisualState.state) {
                ButtonState.PENDING_SAVE -> {
                    // Save mode - perform save
                    performSave()
                }
                ButtonState.RUNNING, ButtonState.IDLE -> {
                    // Toggle mode - toggle VPN state
                    val shouldStart = currentVisualState.state == ButtonState.IDLE
                    onToggle?.invoke(shouldStart)
                }
            }
        }
    }

    private fun animateToVisualState(targetState: ButtonVisualState) {
        // Cancel any existing animation
        currentAnimator?.cancel()

        // Update enabled state immediately
        toggleButton.isEnabled = targetState.enabled

        // Get current colors
        val currentBgColor = toggleButton.backgroundTintList?.defaultColor ?: targetState.bg
        val currentIconColor = toggleButton.iconTint?.defaultColor ?: targetState.fg

        // Check if icon needs to change
        val currentIconTag = toggleButton.tag as? Int
        val needsIconChange = currentIconTag != null && currentIconTag != targetState.icon

        // Create and start animation with icon fade if needed
        currentAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = if (needsIconChange) 300 else 200 // Longer duration for icon change
            addUpdateListener { animator ->
                val fraction = animator.animatedValue as Float

                // Interpolate colors
                val bgColor = ArgbEvaluator().evaluate(fraction, currentBgColor, targetState.bg) as Int
                val iconColor = ArgbEvaluator().evaluate(fraction, currentIconColor, targetState.fg) as Int
                val iconAlpha = if (needsIconChange) (1f - (fraction * 2f)).absoluteValue else 1f
                val iconDimmedColor = ColorUtils.setAlphaComponent(iconColor, (iconAlpha * 255).toInt())


                // Apply colors
                toggleButton.backgroundTintList = ColorStateList.valueOf(bgColor)
                toggleButton.iconTint = ColorStateList.valueOf(iconDimmedColor)

                // Handle icon fade animation
                if (needsIconChange && fraction >= 0.5f && toggleButton.tag != targetState.icon) {
                    toggleButton.setIconResource(targetState.icon)
                    toggleButton.tag = targetState.icon
                }
            }
            start()
        }

        // If icon doesn't need animation, update immediately
        if (!needsIconChange) {
            toggleButton.setIconResource(targetState.icon)
            toggleButton.tag = targetState.icon
        }
    }

    private fun performSave() {
        val trimmedName = draftNameFlow.value.trim()

        lifecycleScope.launch {
            val currentEntry = entryFlow.value

            // Create updated entity based on what changed
            val updatedEntity = if (isConfigEditedFlow.value && decryptedConfiguration != null) {
                // Use the "with configuration" update pathway
                // This requires biometric authentication

                val ret = currentEntry.withNameAndConfig(trimmedName, decryptedConfiguration!!, cryptoManager)
                when (ret) {
                    is Result.Err -> {
                        ret.toast(requireContext())
                        return@launch
                    }
                    is Result.Ok -> ret.value
                }
            } else {
                // Only update the name (no authentication needed)
                currentEntry.copy(name = trimmedName)
            }

            val ret = repository.update(updatedEntity)
            if (ret is Result.Err) {
                ret.toast(requireContext())
                return@launch
            }

            // Reload entry from repository to get fresh data
            val reloadedEntry = repository.listAll().find { it.id == entityId }
            if (reloadedEntry != null) {
                entryFlow.value = reloadedEntry
            }

            // Reset edit state
            isConfigEditedFlow.value = false

            // Notify parent of changes
            onChanged?.invoke()

            // Don't dismiss - keep the sheet open
        }
    }

    private fun updateConfigDisplay() {
        val entry = entryFlow.value
        val hasEncryptedConfig = entry.encryptedConfig != null

        when {
            // State 1: Decrypted config available - show editor
            decryptedConfiguration != null -> {
                codeEditorWrapper.visibility = View.VISIBLE
                decryptPlaceholder.visibility = View.GONE
                addConfigPlaceholder.visibility = View.GONE
                codeEditor.setText(decryptedConfiguration)
            }
            // State 2: Has encrypted config but not decrypted - show decrypt placeholder
            hasEncryptedConfig -> {
                codeEditorWrapper.visibility = View.GONE
                decryptPlaceholder.visibility = View.VISIBLE
                addConfigPlaceholder.visibility = View.GONE
            }
            // State 3: No config at all - show add example placeholder
            else -> {
                codeEditorWrapper.visibility = View.GONE
                decryptPlaceholder.visibility = View.GONE
                addConfigPlaceholder.visibility = View.VISIBLE
            }
        }
    }

    private fun expandFully() {
        val sheet = dialog as? BottomSheetDialog
        if (sheet != null) sheet.behavior.state = BottomSheetBehavior.STATE_EXPANDED
    }

    private fun handleDecryptConfig() {
        lifecycleScope.launch {
            val entry = entryFlow.value
            val config = when (val result = entry.decryptConfig(cryptoManager)) {
                is Result.Ok -> result.value
                is Result.Err -> {
                    result.toast(requireContext())
                    return@launch
                }
            }

            // Set decrypted config and update display
            decryptedConfiguration = config
            updateConfigDisplay()
            expandFully()
        }
    }

    private fun handleAddExampleConfig() {
        decryptedConfiguration = """
            anchor = ["p.EXAMPLE_ANCHOR"]
            suffix = "SUFFIX"
            keypair = "s.EXAMPLE_KEYPAIR"
            
            mtu = 1400
            address = "LOCAL_INTERNAL_ADDR"
            
            mode = "L3"
            
            [[route]]
            to = "0.0.0.0/0"
            via = "REMOTE_INTERNAL_ADDR"

            [[connect_to]]
            endpoint = "REMOTE_IP"
        """.trimIndent()
        isConfigEditedFlow.value = true
        updateConfigDisplay()
        expandFully()
    }


    private fun handleExport() {
        val name = draftNameFlow.value.trim().ifEmpty { "config" }

        // Create intent to save file
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "text/plain"
            putExtra(Intent.EXTRA_TITLE, "$name.toml")
        }
        exportLauncher.launch(intent)
    }

    private fun exportConfigToUri(uri: Uri) {
        lifecycleScope.launch {
            val entry = entryFlow.value
            val config = when (val result = entry.decryptConfig(cryptoManager)) {
                is Result.Ok -> result.value
                is Result.Err -> {
                    result.toast(requireContext())
                    return@launch
                }
            }

            // Check if config is null (no config stored)
            if (config == null) {
                Toast.makeText(requireContext(), "No configuration to export", Toast.LENGTH_SHORT).show()
                return@launch
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
                isConfigEditedFlow.value = true

                // Update UI
                updateConfigDisplay()

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
            .setMessage(getString(R.string.delete_vpn_message, draftNameFlow.value))
            .setPositiveButton(R.string.delete) { _, _ ->
                lifecycleScope.launch {
                    when (val result = repository.delete(entityId)) {
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
            entityId: kotlin.uuid.Uuid,
            repository: VpnConfigRepository,
            cryptoManager: CryptoManager,
            vpnStateManager: VpnStateManager,
            onChanged: () -> Unit,
            onToggle: (Boolean) -> Unit
        ): EditVpnBottomSheet {
            return EditVpnBottomSheet().apply {
                this.entityId = entityId
                this.repository = repository
                this.cryptoManager = cryptoManager
                this.vpnStateManager = vpnStateManager
                this.onChanged = onChanged
                this.onToggle = onToggle
            }
        }
    }
}

