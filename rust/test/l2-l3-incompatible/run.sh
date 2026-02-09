#!/bin/bash
# Run L2-L3 incompatibility test suite

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DRIVER="$SCRIPT_DIR/../common/test-driver.sh"
CONFIG_DIR="$SCRIPT_DIR"
TEST_SCRIPT="$SCRIPT_DIR/test-incompatibility.sh"

echo "Running L2-L3 incompatibility test suite..."
echo ""

bash "$TEST_DRIVER" "$CONFIG_DIR" "$TEST_SCRIPT"
