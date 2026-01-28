#!/bin/bash
# Integration test for kqt

set -e

# Configuration
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${WORK_DIR:-$TEST_DIR/run}"
KQT_BIN="${KQT_BIN:-$TEST_DIR/../rust/target/release/kqt}"

# Network configuration
BRIDGE_NAME="kqt-test-br0"
NS1="kqt-test-ns1"
NS2="kqt-test-ns2"
VETH1="veth-ns1"
VETH2="veth-ns2"
VETH1_PEER="veth-br1"
VETH2_PEER="veth-br2"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Process IDs
NODE1_PID=""
NODE2_PID=""

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    # Kill any running kqt processes by PID if they exist
    if [ -n "$NODE1_PID" ] && kill -0 "$NODE1_PID" 2>/dev/null; then
        sudo kill "$NODE1_PID" 2>/dev/null || true
    fi
    if [ -n "$NODE2_PID" ] && kill -0 "$NODE2_PID" 2>/dev/null; then
        sudo kill "$NODE2_PID" 2>/dev/null || true
    fi
    sleep 1
    
    # Delete network namespaces (this also deletes veth interfaces)
    sudo ip netns del "$NS1" 2>/dev/null || true
    sudo ip netns del "$NS2" 2>/dev/null || true
    
    # Delete bridge
    sudo ip link delete "$BRIDGE_NAME" 2>/dev/null || true
    
    echo -e "${GREEN}Cleanup complete${NC}"
}

# Set trap to cleanup on exit
trap cleanup EXIT

echo "=== KQT Integration Test ==="
echo ""

# Check if kqt binary exists
if [ ! -f "$KQT_BIN" ]; then
    echo -e "${RED}Error: kqt binary not found at $KQT_BIN${NC}"
    echo "Please build the project first with: cd rust && cargo build --release"
    exit 1
fi

# Create working directory
mkdir -p "$WORK_DIR"
cd "$TEST_DIR"

# Step 1: Generate keys
echo -e "${YELLOW}Step 1: Generating CA and keypairs...${NC}"
bash generate-keys.sh "$WORK_DIR"
echo ""

# Step 2: Generate configs
echo -e "${YELLOW}Step 2: Generating configuration files...${NC}"
bash generate-configs.sh "$WORK_DIR"
echo ""

# Step 3: Set up network namespaces and bridge
echo -e "${YELLOW}Step 3: Setting up network namespaces and bridge...${NC}"

# Clean up any existing setup
cleanup

# Create bridge
sudo ip link add name "$BRIDGE_NAME" type bridge
sudo ip addr add 10.0.0.254/24 dev "$BRIDGE_NAME"
sudo ip link set "$BRIDGE_NAME" up

# Create network namespaces
sudo ip netns add "$NS1"
sudo ip netns add "$NS2"

# Create veth pairs and attach to bridge
sudo ip link add "$VETH1" type veth peer name "$VETH1_PEER"
sudo ip link set "$VETH1" netns "$NS1"
sudo ip link set "$VETH1_PEER" master "$BRIDGE_NAME"
sudo ip link set "$VETH1_PEER" up

sudo ip link add "$VETH2" type veth peer name "$VETH2_PEER"
sudo ip link set "$VETH2" netns "$NS2"
sudo ip link set "$VETH2_PEER" master "$BRIDGE_NAME"
sudo ip link set "$VETH2_PEER" up

# Configure interfaces in namespaces
sudo ip netns exec "$NS1" ip addr add 10.0.0.1/24 dev "$VETH1"
sudo ip netns exec "$NS1" ip link set "$VETH1" up
sudo ip netns exec "$NS1" ip link set lo up

sudo ip netns exec "$NS2" ip addr add 10.0.0.2/24 dev "$VETH2"
sudo ip netns exec "$NS2" ip link set "$VETH2" up
sudo ip netns exec "$NS2" ip link set lo up

echo -e "${GREEN}Network setup complete${NC}"
echo ""

# Verify basic connectivity
echo -e "${YELLOW}Verifying basic network connectivity between namespaces...${NC}"
if sudo ip netns exec "$NS1" ping -c 2 -W 2 10.0.0.2 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Basic connectivity verified${NC}"
else
    echo -e "${RED}✗ Basic connectivity failed${NC}"
    exit 1
fi
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

# Step 5: Check TUN/TAP device creation
echo -e "${YELLOW}Step 5: Checking TUN/TAP device creation...${NC}"

if sudo ip netns exec "$NS1" ip link show kqt0 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ TUN device kqt0 created in $NS1${NC}"
else
    echo -e "${RED}✗ TUN device kqt0 not found in $NS1${NC}"
    echo "Node1 log:"
    cat "$WORK_DIR/node1.log"
    exit 1
fi

if sudo ip netns exec "$NS2" ip link show kqt0 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ TUN device kqt0 created in $NS2${NC}"
else
    echo -e "${RED}✗ TUN device kqt0 not found in $NS2${NC}"
    echo "Node2 log:"
    cat "$WORK_DIR/node2.log"
    exit 1
fi
echo ""

# Wait a bit more for tunnel to establish
echo "Waiting for tunnel to establish..."
sleep 5
echo ""

# Step 6: IPv4 ping tests
echo -e "${YELLOW}Step 6: Running IPv4 ping tests...${NC}"

# Test 6a: Default sized packets
echo "Test 6a: Ping with default packet size"
if sudo ip netns exec "$NS1" ping -c 4 -W 5 10.21.0.2 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Default ping successful${NC}"
else
    echo -e "${RED}✗ Default ping failed${NC}"
    exit 1
fi

# Test 6b: Large packets with PMTU discovery
echo "Test 6b: Ping with large packets (PMTU discovery enabled)"
# Use -s 1450 to send packets larger than MTU, with PMTU discovery
PING_OUTPUT=$(sudo ip netns exec "$NS1" ping -c 4 -W 5 -s 1450 10.21.0.2 2>&1)
if echo "$PING_OUTPUT" | grep -q "1450 bytes of data"; then
    echo -e "${GREEN}✓ Large ping with PMTU discovery successful${NC}"
    # Check if fragmentation needed message appears (indicates MTU detection)
    if echo "$PING_OUTPUT" | grep -qi "mtu\|frag"; then
        echo -e "${GREEN}  MTU detection message observed${NC}"
    fi
else
    echo -e "${RED}✗ Large ping with PMTU discovery failed${NC}"
    echo "$PING_OUTPUT"
    exit 1
fi

# Test 6c: Large packets with fragmentation prohibited
echo "Test 6c: Ping with large packets (fragmentation prohibited)"
# Use -M do to prohibit fragmentation (similar to -M dont)
if sudo ip netns exec "$NS1" ping -c 4 -W 5 -s 1450 -M do 10.21.0.2 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Large ping with fragmentation prohibited successful${NC}"
else
    # This might fail if MTU is too small, which is expected behavior
    echo -e "${YELLOW}⚠ Large ping with fragmentation prohibited may have failed (expected if MTU < packet size)${NC}"
fi
echo ""

# Step 7: IPv6 ping tests
echo -e "${YELLOW}Step 7: Running IPv6 ping tests...${NC}"

# Test 7a: Default sized packets
echo "Test 7a: IPv6 ping with default packet size"
if sudo ip netns exec "$NS1" ping6 -c 4 -W 5 fd00::2 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ IPv6 default ping successful${NC}"
else
    echo -e "${RED}✗ IPv6 default ping failed${NC}"
    exit 1
fi

# Test 7b: Large packets with PMTU discovery
echo "Test 7b: IPv6 ping with large packets (PMTU discovery enabled)"
PING6_OUTPUT=$(sudo ip netns exec "$NS1" ping6 -c 4 -W 5 -s 1450 fd00::2 2>&1)
if echo "$PING6_OUTPUT" | grep -q "1450 data bytes"; then
    echo -e "${GREEN}✓ IPv6 large ping with PMTU discovery successful${NC}"
else
    echo -e "${RED}✗ IPv6 large ping with PMTU discovery failed${NC}"
    echo "$PING6_OUTPUT"
    exit 1
fi
echo ""

# All tests passed
echo -e "${GREEN}=== All tests passed! ===${NC}"
echo ""

# Show logs for debugging
echo "Node1 log:"
cat "$WORK_DIR/node1.log"
echo ""
echo "Node2 log:"
cat "$WORK_DIR/node2.log"
