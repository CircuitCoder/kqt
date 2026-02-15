# Android APK Signing Configuration

## Overview

This document describes how to configure APK signing for the Android build workflow.

## GitHub Secrets Setup

To enable APK signing in GitHub Actions, you need to configure the following secrets in your repository:

### Required Secrets

1. **KEYSTORE_BASE64**: Base64-encoded keystore file
2. **KEYSTORE_PASSWORD**: Password for the keystore
3. **KEY_ALIAS**: Alias of the key in the keystore
4. **KEY_PASSWORD**: Password for the key

### Creating a Keystore

If you don't have a keystore yet, create one using the following command:

```bash
keytool -genkey -v -keystore release.keystore -alias your-key-alias -keyalg RSA -keysize 2048 -validity 10000
```

Follow the prompts to set passwords and fill in the certificate information.

### Encoding the Keystore

To encode your keystore file to base64:

```bash
base64 -i release.keystore -o keystore.txt
```

On some systems (like macOS), you might need to use:

```bash
base64 -i release.keystore
```

Copy the entire output (it will be a long string).

### Adding Secrets to GitHub

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add each of the four secrets:
   - `KEYSTORE_BASE64`: Paste the base64-encoded keystore
   - `KEYSTORE_PASSWORD`: Enter your keystore password
   - `KEY_ALIAS`: Enter your key alias
   - `KEY_PASSWORD`: Enter your key password

## Workflow Behavior

- **Pull Requests**: APKs are built but not signed (to protect secrets from untrusted code)
- **Push to main/master**: APKs are built and signed if secrets are configured
- **Manual dispatch**: APKs are built and signed if secrets are configured

If the `KEYSTORE_BASE64` secret is not found, the workflow will log a warning and continue without signing.

## Local Development

For local builds, you can set environment variables:

```bash
export KEYSTORE_FILE=/path/to/your/release.keystore
export KEYSTORE_PASSWORD=your-keystore-password
export KEY_ALIAS=your-key-alias
export KEY_PASSWORD=your-key-password

cd android
./gradlew assembleRelease
```

Alternatively, you can create a `keystore.properties` file (not recommended as it's easy to commit accidentally):

```properties
storeFile=/path/to/your/release.keystore
storePassword=your-keystore-password
keyAlias=your-key-alias
keyPassword=your-key-password
```

**Important**: Never commit your keystore or keystore passwords to version control!

## Security Notes

- The keystore file is automatically excluded from git via `.gitignore`
- Secrets are only available to trusted workflows (not pull requests from forks)
- Keep your keystore and passwords secure - losing them means you cannot update your app on the Play Store
