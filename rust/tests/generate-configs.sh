#!/bin/bash
# Generate TOML configuration files for testing

set -e

# Configuration
OUTPUT_DIR="${1:-.}"
SUFFIX="test.local"
NODE1_LISTEN_PORT="${NODE1_LISTEN_PORT:-9001}"
NODE2_LISTEN_PORT="${NODE2_LISTEN_PORT:-9002}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KQT_BIN="${KQT_BIN:-$SCRIPT_DIR/../target/release/kqt}"

# Ensure keys exist
if [ ! -f "$OUTPUT_DIR/ca-private.txt" ] || [ ! -f "$OUTPUT_DIR/node1-private.txt" ] || [ ! -f "$OUTPUT_DIR/node2-private.txt" ]; then
    echo "Error: Keys not found. Run generate-keys.sh first."
    exit 1
fi

# Read keys
CA_PUBLIC=$(cat "$OUTPUT_DIR/ca-public.cert")
NODE1_PRIVATE=$(cat "$OUTPUT_DIR/node1-private.txt")
NODE2_PRIVATE=$(cat "$OUTPUT_DIR/node2-private.txt")

echo "Generating node1 configuration..."
cat > "$OUTPUT_DIR/node1.toml" <<EOF
# Node 1 Configuration
keypair = "$NODE1_PRIVATE"
anchor = ["$CA_PUBLIC"]
suffix = "$SUFFIX"
mtu = 1400

address = ["10.21.0.1/24", "fd00::1/64"]

listen = "10.0.0.1:$NODE1_LISTEN_PORT"

[[connect_to]]
endpoint = "10.0.0.2:$NODE2_LISTEN_PORT"

[advanced]
initial_outer_mtu = 1452
keepalive = 25
max_idle_timeout = 60
EOF

echo "Generating node2 configuration..."
cat > "$OUTPUT_DIR/node2.toml" <<EOF
# Node 2 Configuration
keypair = "$NODE2_PRIVATE"
anchor = ["$CA_PUBLIC"]
suffix = "$SUFFIX"
mtu = 1400

address = ["10.21.0.2/24", "fd00::2/64"]

listen = "10.0.0.2:$NODE2_LISTEN_PORT"

[[connect_to]]
endpoint = "10.0.0.1:$NODE1_LISTEN_PORT"

[advanced]
initial_outer_mtu = 1452
keepalive = 25
max_idle_timeout = 60
EOF

echo "Configuration files generated successfully:"
echo "  - $OUTPUT_DIR/node1.toml"
echo "  - $OUTPUT_DIR/node2.toml"
