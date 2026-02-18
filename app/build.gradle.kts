import com.android.build.OutputFile

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.ksp)
}

android {
    namespace = "plus.meow.kqt"
    compileSdk = 36

    defaultConfig {
        applicationId = "plus.meow.kqt"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    val keystorePassword = System.getenv("KEYSTORE_PASSWORD")?.trim()

    signingConfigs {
        create("release") {
            if (keystorePassword != null) {
                storeFile = file("keys/ci.keystore")
                storePassword = keystorePassword
                keyAlias = "apk"
                keyPassword = keystorePassword
            }
        }
    }

    buildTypes {
        debug {
            // Only sign if KEYSTORE_PASSWORD is available
            if (keystorePassword != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Only sign if KEYSTORE_PASSWORD is available
            if (keystorePassword != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
    
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a")
            isUniversalApk = true
        }
    }
    
    compileOptions {
        sourceCompatibility = org.gradle.api.JavaVersion.VERSION_17
        targetCompatibility = org.gradle.api.JavaVersion.VERSION_17
    }
}

val appExtension = components.findByName("android")
    ?: extensions.getByType(com.android.build.gradle.AppExtension::class.java)

if (appExtension is com.android.build.gradle.AppExtension) {
    appExtension.applicationVariants.all {
        val variant = this
        outputs.all {
            val output = this as com.android.build.gradle.internal.api.BaseVariantOutputImpl

            // Safe filter extraction
            val abi = output.getFilter(OutputFile.ABI) ?: "universal"

            // Set the name
            output.outputFileName = "kqt-${abi}-${variant.versionName}-${variant.buildType.name}.apk"
        }
    }
}

kotlin {
    jvmToolchain(17)
    compilerOptions {
        languageVersion = org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_3
        freeCompilerArgs.add("-opt-in=kotlin.uuid.ExperimentalUuidApi")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.recyclerview)
    implementation(libs.androidx.coordinatorlayout)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.material)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.biometric)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.jna) {
        artifact {
            type = "aar"
        }
    }
    implementation(libs.sora.editor)
    implementation(libs.sora.editor.language.textmate)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}