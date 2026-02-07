package plus.meow.kqt

import android.content.Context
import android.os.Bundle
import android.util.DisplayMetrics
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.TextView
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import java.util.UUID

class EditVpnBottomSheet : BottomSheetDialogFragment() {

    private var entryId: UUID? = null
    private var onSave: ((UUID, String) -> Unit)? = null
    private var onToggle: ((UUID, Boolean) -> Unit)? = null
    private var nameValidator: ((UUID, String) -> Boolean)? = null
    private var entryProvider: ((UUID) -> VPNEntry?)? = null

    private lateinit var nameInput: TextInputEditText
    private lateinit var toggleButton: MaterialButton
    private lateinit var saveButton: MaterialButton
    private lateinit var configText: TextView

    private var draftName: String = ""
    private var isRunning: Boolean = false

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.sheet_edit_vpn, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val id = entryId ?: run {
            dismiss()
            return
        }

        val entry = entryProvider?.invoke(id) ?: run {
            dismiss()
            return
        }

        initializeViews(view)
        setupInitialState(entry)
        setupListeners(id)
        configureBottomSheet(view)
    }

    private fun initializeViews(view: View) {
        nameInput = view.findViewById(R.id.nameInput)
        toggleButton = view.findViewById(R.id.toggleIconButton)
        saveButton = view.findViewById(R.id.saveButton)
        configText = view.findViewById(R.id.configText)

        val exportButton = view.findViewById<MaterialButton>(R.id.exportButton)
        val importButton = view.findViewById<MaterialButton>(R.id.importButton)

        // Set up export/import buttons (TODO: implement functionality)
        exportButton.setOnClickListener {
            // TODO: hook export flow.
        }

        importButton.setOnClickListener {
            // TODO: hook import flow.
        }
    }

    private fun setupInitialState(entry: VPNEntry) {
        draftName = entry.name
        nameInput.setText(draftName)
        configText.text = entry.cfg
        toggleButton.isChecked = isRunning
        updateSaveEnabled()
    }

    private fun setupListeners(id: UUID) {
        nameInput.doAfterTextChanged { text ->
            draftName = text?.toString()?.trim().orEmpty()
            updateSaveEnabled()
        }

        toggleButton.addOnCheckedChangeListener { _, checked ->
            onToggle?.invoke(id, checked)
        }

        saveButton.setOnClickListener {
            if (validateAndSave(id)) {
                dismiss()
            }
        }
    }

    private fun validateAndSave(id: UUID): Boolean {
        val trimmedName = draftName.trim()

        // Validate name is not empty
        if (trimmedName.isEmpty()) {
            nameInput.error = getString(R.string.vpn_name_empty)
            return false
        }

        // Validate name length
        if (trimmedName.length > 50) {
            nameInput.error = getString(R.string.vpn_name_too_long)
            return false
        }

        // Check for name conflicts
        val hasConflict = nameValidator?.invoke(id, trimmedName) == false
        if (hasConflict) {
            nameInput.error = getString(R.string.vpn_name_conflict)
            return false
        }

        // Save and close
        onSave?.invoke(id, trimmedName)
        return true
    }

    private fun updateSaveEnabled() {
        val entry = entryId?.let { entryProvider?.invoke(it) }
        val changed = entry != null && draftName.trim() != entry.name
        val trimmedName = draftName.trim()
        val isEmpty = trimmedName.isEmpty()
        val hasConflict = entryId?.let { nameValidator?.invoke(it, trimmedName) } == false

        nameInput.error = when {
            isEmpty && changed -> getString(R.string.vpn_name_empty)
            hasConflict -> getString(R.string.vpn_name_conflict)
            else -> null
        }

        saveButton.isEnabled = changed && !isEmpty && !hasConflict
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
            entryId: UUID,
            isRunning: Boolean,
            entryProvider: (UUID) -> VPNEntry?,
            nameValidator: (UUID, String) -> Boolean,
            onSave: (UUID, String) -> Unit,
            onToggle: (UUID, Boolean) -> Unit
        ): EditVpnBottomSheet {
            return EditVpnBottomSheet().apply {
                this.entryId = entryId
                this.isRunning = isRunning
                this.entryProvider = entryProvider
                this.nameValidator = nameValidator
                this.onSave = onSave
                this.onToggle = onToggle
            }
        }
    }
}

