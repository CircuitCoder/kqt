# Android main application

Scaffolding taken from https://github.com/rust-mobile/rust-android-examples

# Gradle Build
```
export ANDROID_NDK_HOME="path/to/ndk"
export ANDROID_HOME="path/to/sdk"

rustup target add aarch64-linux-android
cargo install cargo-ndk

cargo ndk -t arm64-v8a -o app/src/main/jniLibs/  build
gradlew build
gradlew installDebug
adb shell am start -n plus.meow.kqt/.MainActivity
```
