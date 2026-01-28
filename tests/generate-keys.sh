#!/bin/bash
# Generate CA and keypairs for testing

set -e

# Configuration
SUFFIX="test.local"
OUTPUT_DIR="${1:-.}"
KQT_BIN="${KQT_BIN:-$(dirname "$0")/../rust/target/release/kqt}"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

echo "Generating CA keypair..."
# Generate self-signed CA
CA_PRIVATE=$("$KQT_BIN" keygen private --self-signed --suffix "$SUFFIX")
echo "$CA_PRIVATE" > "$OUTPUT_DIR/ca-private.key"

# Extract CA public certificate
CA_PUBLIC=$(echo -n "$CA_PRIVATE" | "$KQT_BIN" keygen public --format pem --suffix "$SUFFIX")
echo "$CA_PUBLIC" > "$OUTPUT_DIR/ca.pem"

echo "Generating node1 keypair..."
# Generate node1 keypair signed by CA
NODE1_PRIVATE=$(echo -n "$CA_PRIVATE" | "$KQT_BIN" keygen private --suffix "$SUFFIX")
echo "$NODE1_PRIVATE" > "$OUTPUT_DIR/node1-private.key"

# Extract node1 public certificate
NODE1_PUBLIC=$(echo -n "$NODE1_PRIVATE" | "$KQT_BIN" keygen public --format pem --suffix "$SUFFIX")
echo "$NODE1_PUBLIC" > "$OUTPUT_DIR/node1.pem"

echo "Generating node2 keypair..."
# Generate node2 keypair signed by CA
NODE2_PRIVATE=$(echo -n "$CA_PRIVATE" | "$KQT_BIN" keygen private --suffix "$SUFFIX")
echo "$NODE2_PRIVATE" > "$OUTPUT_DIR/node2-private.key"

# Extract node2 public certificate
NODE2_PUBLIC=$(echo -n "$NODE2_PRIVATE" | "$KQT_BIN" keygen public --format pem --suffix "$SUFFIX")
echo "$NODE2_PUBLIC" > "$OUTPUT_DIR/node2.pem"

echo "Keys generated successfully in $OUTPUT_DIR:"
echo "  - ca-private.key, ca.pem"
echo "  - node1-private.key, node1.pem"
echo "  - node2-private.key, node2.pem"
