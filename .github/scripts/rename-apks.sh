#!/bin/bash
# Script to rename APK files with standard naming convention
# Usage: rename-apks.sh <build-type> <version> <commit>

set -e

BUILD_TYPE=$1
VERSION=$2
COMMIT=$3

if [ -z "$BUILD_TYPE" ] || [ -z "$VERSION" ] || [ -z "$COMMIT" ]; then
    echo "Usage: $0 <build-type> <version> <commit>"
    exit 1
fi

APK_DIR="android/app/build/outputs/apk/$BUILD_TYPE"

if [ ! -d "$APK_DIR" ]; then
    echo "Error: APK directory does not exist: $APK_DIR"
    echo "Make sure the build has completed successfully before renaming APKs"
    exit 1
fi

cd "$APK_DIR"

# Enable nullglob to handle case where no APK files exist
shopt -s nullglob

for apk in *.apk; do
    if [[ "$apk" == *"arm64-v8a"* ]]; then
        mv "$apk" "kqt-$BUILD_TYPE-arm64-v8a-$VERSION-$COMMIT.apk"
    elif [[ "$apk" == *"armeabi-v7a"* ]]; then
        mv "$apk" "kqt-$BUILD_TYPE-armeabi-v7a-$VERSION-$COMMIT.apk"
    elif [[ "$apk" == *"universal"* ]]; then
        mv "$apk" "kqt-$BUILD_TYPE-universal-$VERSION-$COMMIT.apk"
    else
        echo "Warning: Unexpected APK file does not match known patterns: $apk"
    fi
done

echo "Renamed APKs in $BUILD_TYPE:"
if ls *.apk >/dev/null 2>&1; then
    ls -1 *.apk
else
    echo "Warning: No APK files found in $APK_DIR"
fi
