package plus.meow.kqt.editor

import android.content.Context
import io.github.rosemoe.sora.langs.textmate.TextMateColorScheme
import io.github.rosemoe.sora.langs.textmate.TextMateLanguage
import io.github.rosemoe.sora.langs.textmate.registry.FileProviderRegistry
import io.github.rosemoe.sora.langs.textmate.registry.GrammarRegistry
import io.github.rosemoe.sora.langs.textmate.registry.ThemeRegistry
import io.github.rosemoe.sora.langs.textmate.registry.dsl.languages
import io.github.rosemoe.sora.langs.textmate.registry.provider.AssetsFileResolver
import org.eclipse.tm4e.core.registry.IThemeSource

/**
 * Factory for creating TOML language support using TextMate grammar.
 */
object TomlLanguageFactory {

    private var initialized = false

    /**
     * Initialize the TextMate registry with TOML grammar and themes.
     * Must be called once before creating language instances.
     */
    fun initialize(context: Context) {
        if (initialized) return

        try {
            // Register assets file provider for grammar files
            FileProviderRegistry.getInstance().addFileProvider(
                AssetsFileResolver(context.assets)
            )

            // Load TOML grammar definition
            GrammarRegistry.getInstance().loadGrammars(
                languages {
                    language("toml") {
                        grammar = "toml.tmLanguage.json"
                        scopeName = "source.toml"
                        languageConfiguration = "toml-language-configuration.json"
                    }
                }
            )

            // Load One Dark and One Light themes
            loadThemes(context)

            initialized = true
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun loadThemes(context: Context) {
        try {
            val themeRegistry = ThemeRegistry.getInstance()

            // Load One Dark theme
            themeRegistry.loadTheme(
                IThemeSource.fromInputStream(
                    context.assets.open("one-dark.json"),
                    "one-dark.json",
                    null
                )
            )

            // Load One Light theme
            themeRegistry.loadTheme(
                IThemeSource.fromInputStream(
                    context.assets.open("one-light.json"),
                    "one-light.json",
                    null
                )
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * Create a new TOML language instance. Must call initialize() first.
     */
    fun createLanguage(): TextMateLanguage {
        return TextMateLanguage.create("source.toml", true)
    }

    fun createColorScheme(isDarkMode: Boolean): TextMateColorScheme {
        val themeName = if (isDarkMode) "one-dark" else "one-light"
        val registry = ThemeRegistry.getInstance()
        registry.setTheme(themeName)
        return TextMateColorScheme.create(registry)
    }
}

