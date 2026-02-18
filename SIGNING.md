# Android APK Signing Configuration

## Overview

This document describes the APK signing setup for the Android build workflow.

## CI Keystore

The repository includes a debug signing keystore at `android/app/keys/ci.keystore` that is used for signing APKs in CI builds.

### Keystore Details

- **Location**: `android/app/keys/ci.keystore`
- **Alias**: `apk`
- **Algorithm**: ECDSA (EC with 256-bit key)
- **Format**: PKCS12
- **Validity**: 10 years

This is a **debug signing keystore** used only for development and CI builds. It is password-protected and committed to the repository for convenience.

## GitHub Secrets Setup

To enable APK signing in GitHub Actions, you need to configure the following secret:

### Required Secret

- **KEYSTORE_PASSWORD**: Password for the CI keystore

### Adding Secret to GitHub

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add the secret:
   - Name: `KEYSTORE_PASSWORD`
   - Value: The keystore password

## Workflow Behavior

- **All branches**: APKs are built and signed using the CI keystore
- The keystore password is provided via the `KEYSTORE_PASSWORD` secret
- If the secret is not configured, the build will fail with an error message

## Creating a New CI Keystore

If you need to regenerate the CI keystore (e.g., if compromised), use:

```bash
cd android/app/keys
keytool -genkeypair -v -keystore ci.keystore -alias apk \
  -keyalg EC -keysize 256 -validity 3650 -storetype PKCS12 \
  -storepass "your-password" -keypass "your-password" \
  -dname "CN=KQT CI, OU=Development, O=KQT, L=Unknown, ST=Unknown, C=US"
```

Replace `"your-password"` with your chosen password, and update the `KEYSTORE_PASSWORD` secret in GitHub.

## Local Development

For local builds, set the environment variable:

```bash
export KEYSTORE_PASSWORD=your-keystore-password
cd android
./gradlew assembleRelease
```

Or provide the password inline:

```bash
cd android
KEYSTORE_PASSWORD=your-keystore-password ./gradlew assembleRelease
```

## Production Signing

**Important**: The CI keystore is for **development and testing only**. For production releases to the Google Play Store:

1. Create a separate production keystore with strong security
2. Store it securely (not in version control)
3. Use a different signing configuration for production builds
4. Never share or commit your production keystore

## Security Notes

- The CI keystore is intentionally committed to the repository for CI convenience
- It uses password protection as an additional security layer
- This is appropriate for debug/development builds but not for production releases
- Keep your production keystore separate and secure
