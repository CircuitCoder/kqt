#!/bin/bash
# Run L2 connectivity test suite using C test runner

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_RUNNER="$SCRIPT_DIR/../test-runner"
NODE1_CONFIG="$SCRIPT_DIR/node1.toml"
NODE2_CONFIG="$SCRIPT_DIR/node2.toml"
TEST_SCRIPT="$SCRIPT_DIR/test-connectivity.sh"

# Build test runner if needed
if [ ! -f "$TEST_RUNNER" ]; then
    echo "Building test runner..."
    cd "$SCRIPT_DIR/.."
    make
fi

# Set KQT_BIN to absolute path if not already set
if [ -z "$KQT_BIN" ]; then
    export KQT_BIN="$(cd "$SCRIPT_DIR/../.." && pwd)/target/release/kqt"
fi

echo "Running L2 connectivity test suite..."
echo ""

# The C test runner expects: node1_config node2_config node1_script node2_script
# We use the same script for both since the test runs in node1's namespace
sudo -E "$TEST_RUNNER" "$NODE1_CONFIG" "$NODE2_CONFIG" "$TEST_SCRIPT" "$TEST_SCRIPT"
