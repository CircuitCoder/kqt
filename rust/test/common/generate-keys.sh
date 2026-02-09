#!/bin/bash
# Generate CA and keypairs for testing

set -e

# Configuration
SUFFIX="test.local"
OUTPUT_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KQT_BIN="${KQT_BIN:-$SCRIPT_DIR/../../target/release/kqt}"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Validate KQT_BIN exists and is executable
if [ ! -f "$KQT_BIN" ]; then
    echo "Error: kqt binary not found at $KQT_BIN"
    echo "Please build the project first with: cd rust && cargo build --release"
    exit 1
fi

if [ ! -x "$KQT_BIN" ]; then
    echo "Error: kqt binary at $KQT_BIN is not executable"
    exit 1
fi

echo "Generating CA keypair..."
# Generate self-signed CA
CA_PRIVATE=$("$KQT_BIN" keygen private --self-signed --suffix "$SUFFIX")
echo "$CA_PRIVATE" > "$OUTPUT_DIR/ca-private.txt"

# Extract CA public certificate (string format)
CA_PUBLIC=$(echo -n "$CA_PRIVATE" | "$KQT_BIN" keygen public --format string --suffix "$SUFFIX")
echo "$CA_PUBLIC" > "$OUTPUT_DIR/ca-public.cert"

echo "Generating node1 keypair..."
# Generate node1 keypair signed by CA
NODE1_PRIVATE=$(echo -n "$CA_PRIVATE" | "$KQT_BIN" keygen private --suffix "$SUFFIX")
echo "$NODE1_PRIVATE" > "$OUTPUT_DIR/node1-private.txt"

# Extract node1 public certificate (string format)
NODE1_PUBLIC=$(echo -n "$NODE1_PRIVATE" | "$KQT_BIN" keygen public --format string --suffix "$SUFFIX")
echo "$NODE1_PUBLIC" > "$OUTPUT_DIR/node1-public.cert"

echo "Generating node2 keypair..."
# Generate node2 keypair signed by CA
NODE2_PRIVATE=$(echo -n "$CA_PRIVATE" | "$KQT_BIN" keygen private --suffix "$SUFFIX")
echo "$NODE2_PRIVATE" > "$OUTPUT_DIR/node2-private.txt"

# Extract node2 public certificate (string format)
NODE2_PUBLIC=$(echo -n "$NODE2_PRIVATE" | "$KQT_BIN" keygen public --format string --suffix "$SUFFIX")
echo "$NODE2_PUBLIC" > "$OUTPUT_DIR/node2-public.cert"

echo "Keys generated successfully in $OUTPUT_DIR:"
echo "  - ca-private.txt, ca-public.cert"
echo "  - node1-private.txt, node1-public.cert"
echo "  - node2-private.txt, node2-public.cert"
