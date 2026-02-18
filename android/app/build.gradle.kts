import com.android.build.OutputFile

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.ksp)
}

val appVersionName = "1.0.0"

android {
    namespace = "plus.meow.kqt"
    compileSdk = 36

    defaultConfig {
        applicationId = "plus.meow.kqt"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = appVersionName

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

tasks.register<Copy>("collectAndRenameApks") {
    description = "Copies, flattens, and renames APKs to the upload directory"
    group = "distribution"

    // Source: The standard output directory
    from(layout.buildDirectory.dir("outputs/apk"))

    // Destination: Your upload folder
    into(layout.buildDirectory.dir("outputs/collected"))

    include("**/*.apk")

    // Flattening and Renaming Logic
    eachFile {
        val matcher = "(.*)-(arm64-v8a|armeabi-v7a|universal)-(.*)\\.apk".toRegex().matchEntire(name)

        if (matcher != null) {
            val (prefix, abi, buildType) = matcher.destructured
            path = "kqt-$abi-$appVersionName-$buildType.apk"
        } else {
            path = name.replace(".apk", "-$appVersionName.apk")
        }
    }

    // Ensure we don't copy the empty "debug"/"release" folders
    includeEmptyDirs = false
}

tasks.named("assemble") {
    finalizedBy("collectAndRenameApks")
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
