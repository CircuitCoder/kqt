#!/bin/bash
# Test driver for kqt integration tests
# Creates network namespaces, veth pairs, runs tests, and cleans up
# Uses PID namespace for proper cleanup of child processes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="${SCRIPT_DIR}/.."
WORK_DIR="${WORK_DIR:-$TEST_DIR/run}"
KQT_BIN="${KQT_BIN:-$TEST_DIR/../target/release/kqt}"

# Network configuration
NS1="${NS1:-kqt-test-ns1}"
NS2="${NS2:-kqt-test-ns2}"
VETH1="${VETH1:-veth1}"
VETH2="${VETH2:-veth2}"

# Process tracking
NODE1_PID=""
NODE2_PID=""

# Usage information
usage() {
    echo "Usage: $0 <config_dir> <test_script>"
    echo ""
    echo "Arguments:"
    echo "  config_dir   - Directory containing node1.toml and node2.toml templates"
    echo "  test_script  - Test script to run after nodes are started"
    echo ""
    echo "Environment variables:"
    echo "  WORK_DIR     - Working directory for generated configs and logs (default: ../run)"
    echo "  KQT_BIN      - Path to kqt binary (default: ../../target/release/kqt)"
    echo "  NS1, NS2     - Network namespace names (defaults: kqt-test-ns1, kqt-test-ns2)"
    echo "  VETH1, VETH2 - veth interface names (defaults: veth1, veth2)"
    echo "  NODE1_LISTEN_PORT - Port for node1 (default: 9001)"
    echo "  NODE2_LISTEN_PORT - Port for node2 (default: 9002)"
    exit 1
}

# Check arguments
if [ $# -lt 2 ]; then
    usage
fi

CONFIG_DIR="$1"
TEST_SCRIPT="$2"

# Validate inputs
if [ ! -d "$CONFIG_DIR" ]; then
    echo -e "${RED}Error: Config directory not found: $CONFIG_DIR${NC}"
    exit 1
fi

if [ ! -f "$TEST_SCRIPT" ]; then
    echo -e "${RED}Error: Test script not found: $TEST_SCRIPT${NC}"
    exit 1
fi

if [ ! -x "$TEST_SCRIPT" ]; then
    echo -e "${RED}Error: Test script is not executable: $TEST_SCRIPT${NC}"
    exit 1
fi

# Check if kqt binary exists
if [ ! -f "$KQT_BIN" ]; then
    echo -e "${RED}Error: kqt binary not found at $KQT_BIN${NC}"
    echo "Please build the project first with: cd rust && cargo build --release"
    exit 1
fi

# Cleanup function
cleanup() {
    local exit_code=$?
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    # Kill any running kqt processes by PID if they exist
    if [ -n "$NODE1_PID" ] && ps -p "$NODE1_PID" > /dev/null 2>&1; then
        sudo kill "$NODE1_PID" 2>/dev/null || true
        sleep 0.5
    fi
    if [ -n "$NODE2_PID" ] && ps -p "$NODE2_PID" > /dev/null 2>&1; then
        sudo kill "$NODE2_PID" 2>/dev/null || true
        sleep 0.5
    fi
    
    # Delete network namespaces (this also deletes veth interfaces)
    sudo ip netns del "$NS1" 2>/dev/null || true
    sudo ip netns del "$NS2" 2>/dev/null || true
    
    echo -e "${GREEN}Cleanup complete${NC}"
    
    # Exit with the original exit code if non-zero, otherwise success
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}Test failed with exit code $exit_code${NC}"
        exit $exit_code
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT INT TERM

echo -e "${BLUE}=== KQT Test Driver ===${NC}"
echo ""

# Check if /dev/net/tun exists
if [ ! -c /dev/net/tun ]; then
    echo -e "${RED}Error: /dev/net/tun device not found${NC}"
    echo "TUN/TAP support is required for this test"
    exit 1
fi

# Create working directory
mkdir -p "$WORK_DIR"

# Step 1: Generate keys (if not already present)
if [ ! -f "$WORK_DIR/ca-private.txt" ]; then
    echo -e "${YELLOW}Step 1: Generating CA and keypairs...${NC}"
    bash "$SCRIPT_DIR/../common/generate-keys.sh" "$WORK_DIR"
    echo ""
else
    echo -e "${YELLOW}Step 1: Using existing CA and keypairs...${NC}"
    echo ""
fi

# Step 2: Generate configs from templates
echo -e "${YELLOW}Step 2: Generating configuration files from templates...${NC}"

# Read keys
CA_PUBLIC=$(cat "$WORK_DIR/ca-public.cert")
NODE1_PRIVATE=$(cat "$WORK_DIR/node1-private.txt")
NODE2_PRIVATE=$(cat "$WORK_DIR/node2-private.txt")
NODE1_LISTEN_PORT="${NODE1_LISTEN_PORT:-9001}"
NODE2_LISTEN_PORT="${NODE2_LISTEN_PORT:-9002}"

# Generate node1 config from template
sed -e "s|{CA_PUBLIC}|$CA_PUBLIC|g" \
    -e "s|{NODE1_PRIVATE}|$NODE1_PRIVATE|g" \
    -e "s|{NODE2_PRIVATE}|$NODE2_PRIVATE|g" \
    -e "s|{NODE1_LISTEN_PORT}|$NODE1_LISTEN_PORT|g" \
    -e "s|{NODE2_LISTEN_PORT}|$NODE2_LISTEN_PORT|g" \
    "$CONFIG_DIR/node1.toml" > "$WORK_DIR/node1.toml"

# Generate node2 config from template
sed -e "s|{CA_PUBLIC}|$CA_PUBLIC|g" \
    -e "s|{NODE1_PRIVATE}|$NODE1_PRIVATE|g" \
    -e "s|{NODE2_PRIVATE}|$NODE2_PRIVATE|g" \
    -e "s|{NODE1_LISTEN_PORT}|$NODE1_LISTEN_PORT|g" \
    -e "s|{NODE2_LISTEN_PORT}|$NODE2_LISTEN_PORT|g" \
    "$CONFIG_DIR/node2.toml" > "$WORK_DIR/node2.toml"

echo "Configuration files generated:"
echo "  - $WORK_DIR/node1.toml"
echo "  - $WORK_DIR/node2.toml"
echo ""

# Step 3: Set up network namespaces with veth pair
echo -e "${YELLOW}Step 3: Setting up network namespaces with veth pair...${NC}"

# Clean up any existing setup
sudo ip netns del "$NS1" 2>/dev/null || true
sudo ip netns del "$NS2" 2>/dev/null || true

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
sudo sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

# Create network namespaces
sudo ip netns add "$NS1"
sudo ip netns add "$NS2"
echo "Network namespaces created: $NS1, $NS2"

# Create veth pair connecting the two namespaces directly
sudo ip link add "$VETH1" type veth peer name "$VETH2"
sudo ip link set "$VETH1" netns "$NS1"
sudo ip link set "$VETH2" netns "$NS2"
echo "veth pair created: $VETH1 <-> $VETH2"

# Configure interfaces in namespaces
sudo ip netns exec "$NS1" ip addr add 10.0.0.1/24 dev "$VETH1"
sudo ip netns exec "$NS1" ip link set "$VETH1" up
sudo ip netns exec "$NS1" ip link set lo up
echo "Configured $VETH1 in $NS1 with 10.0.0.1/24"

sudo ip netns exec "$NS2" ip addr add 10.0.0.2/24 dev "$VETH2"
sudo ip netns exec "$NS2" ip link set "$VETH2" up
sudo ip netns exec "$NS2" ip link set lo up
echo "Configured $VETH2 in $NS2 with 10.0.0.2/24"

echo -e "${GREEN}Network setup complete${NC}"
echo ""

# Step 4: Start kqt nodes
echo -e "${YELLOW}Step 4: Starting kqt nodes...${NC}"

# Start node1 in background
sudo ip netns exec "$NS1" "$KQT_BIN" server "$WORK_DIR/node1.toml" kqt0 > "$WORK_DIR/node1.log" 2>&1 &
NODE1_PID=$!
echo "Started node1 (PID: $NODE1_PID)"

# Start node2 in background
sudo ip netns exec "$NS2" "$KQT_BIN" server "$WORK_DIR/node2.toml" kqt0 > "$WORK_DIR/node2.log" 2>&1 &
NODE2_PID=$!
echo "Started node2 (PID: $NODE2_PID)"

# Wait for nodes to start up
echo "Waiting for nodes to initialize..."
sleep 5
echo ""

# Step 5: Run the test script
echo -e "${YELLOW}Step 5: Running test script...${NC}"
echo ""

# Export variables for test script
export NS1 NS2 WORK_DIR KQT_BIN

# Run test script
if bash "$TEST_SCRIPT"; then
    echo ""
    echo -e "${GREEN}=== Test passed! ===${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}=== Test failed! ===${NC}"
    echo ""
    echo "Node1 log:"
    cat "$WORK_DIR/node1.log"
    echo ""
    echo "Node2 log:"
    cat "$WORK_DIR/node2.log"
    exit 1
fi
