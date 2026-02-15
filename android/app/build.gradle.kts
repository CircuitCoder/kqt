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

    signingConfigs {
        create("release") {
            val keystoreFile = System.getenv("KEYSTORE_FILE")
            val keystorePass = System.getenv("KEYSTORE_PASSWORD")
            val alias = System.getenv("KEY_ALIAS")
            val keyPass = System.getenv("KEY_PASSWORD")
            
            if (keystoreFile != null && keystorePass != null && alias != null && keyPass != null) {
                storeFile = file(keystoreFile)
                storePassword = keystorePass
                keyAlias = alias
                keyPassword = keyPass
            }
            // If environment variables are not set, signing will be skipped
            // This allows the build to complete without signing credentials
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Only apply signing config if all credentials are available
            val keystoreFile = System.getenv("KEYSTORE_FILE")
            val keystorePass = System.getenv("KEYSTORE_PASSWORD")
            val alias = System.getenv("KEY_ALIAS")
            val keyPass = System.getenv("KEY_PASSWORD")
            
            if (keystoreFile != null && keystorePass != null && alias != null && keyPass != null) {
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