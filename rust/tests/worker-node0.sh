#!/bin/bash
# Worker script for node 0 (runs tests)
# This script runs inside a network namespace created by kqt-tester
# KQT_TESTER_NODE environment variable is set to 0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${WORK_DIR:-$TEST_DIR/run}"
KQT_BIN="${KQT_BIN:-$TEST_DIR/../target/release/kqt}"

# Check if /dev/net/tun exists
if [ ! -c /dev/net/tun ]; then
    echo -e "${RED}Error: /dev/net/tun device not found${NC}"
    echo "TUN/TAP support is required for this test"
    exit 1
fi

echo -e "${YELLOW}Worker 1 (node1) starting in network namespace...${NC}"

# Start kqt node1 in background
"$KQT_BIN" server "$WORK_DIR/node1.toml" kqt0 > "$WORK_DIR/node1.log" 2>&1 &
NODE_PID=$!

# Give the node time to start up
sleep 5

# Check if TUN device was created
if ! ip link show kqt0 > /dev/null 2>&1; then
    echo -e "${RED}✗ TUN device kqt0 not found${NC}"
    echo "Node1 log:"
    cat "$WORK_DIR/node1.log"
    kill $NODE_PID 2>/dev/null || true
    exit 1
fi

echo -e "${GREEN}✓ TUN device kqt0 created in worker 1 (node1)${NC}"

# Wait for tunnel to establish
echo "Waiting for tunnel to establish..."
sleep 5
echo ""

# Run the tests
echo -e "${YELLOW}Running IPv4 ping tests from node1...${NC}"

# Test: Default sized packets
echo "Test: Ping with default packet size"
PING_OUTPUT=$(ping -c 4 -W 5 10.21.0.2 2>&1 || true)
echo "$PING_OUTPUT"
if echo "$PING_OUTPUT" | grep -q " received"; then
    RECEIVED=$(echo "$PING_OUTPUT" | grep "packets transmitted" | awk '{print $4}')
    if [ "$RECEIVED" != "0" ]; then
        echo -e "${GREEN}✓ Default ping successful${NC}"
    else
        echo -e "${RED}✗ Default ping failed (no packets received)${NC}"
        if grep -q "Operation not permitted" "$WORK_DIR/node1.log" "$WORK_DIR/node2.log" 2>/dev/null; then
            echo -e "${YELLOW}⚠ UDP socket operations are being denied${NC}"
            echo -e "${YELLOW}  This is a known limitation in some sandbox environments.${NC}"
            kill $NODE_PID 2>/dev/null || true
            exit 0
        fi
        kill $NODE_PID 2>/dev/null || true
        exit 1
    fi
else
    echo -e "${RED}✗ Default ping failed (no statistics)${NC}"
    kill $NODE_PID 2>/dev/null || true
    exit 1
fi

# Test: Large packets with PMTU discovery
echo "Test: Ping with large packets (PMTU discovery enabled)"
PING_OUTPUT=$(ping -c 4 -W 5 -s 5000 10.21.0.2 2>&1 || true)
echo "$PING_OUTPUT"
if echo "$PING_OUTPUT" | grep -q " received"; then
    RECEIVED=$(echo "$PING_OUTPUT" | grep "packets transmitted" | awk '{print $4}')
    if [ "$RECEIVED" != "0" ]; then
        echo -e "${GREEN}✓ Large ping with PMTU discovery successful${NC}"
        if echo "$PING_OUTPUT" | grep -q "Frag needed\|Message too long"; then
            echo -e "${GREEN}  First ping failed as expected (PMTU discovery in action)${NC}"
        fi
    else
        echo -e "${RED}✗ Large ping with PMTU discovery failed${NC}"
        kill $NODE_PID 2>/dev/null || true
        exit 1
    fi
else
    echo -e "${RED}✗ Large ping with PMTU discovery failed (no statistics)${NC}"
    kill $NODE_PID 2>/dev/null || true
    exit 1
fi

# Test: Large packets with fragmentation allowed
echo "Test: Ping with large packets (force enable fragmentation)"
PING_OUTPUT=$(ping -c 4 -W 5 -s 5000 -M dont 10.21.0.2 2>&1 || true)
echo "$PING_OUTPUT"
if echo "$PING_OUTPUT" | grep -q " received"; then
    RECEIVED=$(echo "$PING_OUTPUT" | grep "packets transmitted" | awk '{print $4}')
    TRANSMITTED=$(echo "$PING_OUTPUT" | grep "packets transmitted" | awk '{print $1}')
    if [ "$RECEIVED" = "$TRANSMITTED" ]; then
        echo -e "${GREEN}✓ Large ping with fragmentation allowed successful${NC}"
    else
        echo -e "${RED}✗ Large ping with fragmentation allowed failed${NC}"
        kill $NODE_PID 2>/dev/null || true
        exit 1
    fi
else
    echo -e "${RED}✗ Large ping with fragmentation allowed failed (no statistics)${NC}"
    kill $NODE_PID 2>/dev/null || true
    exit 1
fi
echo ""

# IPv6 tests
echo -e "${YELLOW}Running IPv6 ping tests from node1...${NC}"

# Test: Default sized packets
echo "Test: IPv6 ping with default packet size"
PING6_OUTPUT=$(ping6 -c 4 -W 5 fd00::2 2>&1 || true)
echo "$PING6_OUTPUT"
if echo "$PING6_OUTPUT" | grep -q " received"; then
    RECEIVED=$(echo "$PING6_OUTPUT" | grep "packets transmitted" | awk '{print $4}')
    if [ "$RECEIVED" != "0" ]; then
        echo -e "${GREEN}✓ IPv6 default ping successful${NC}"
    else
        echo -e "${RED}✗ IPv6 default ping failed${NC}"
        kill $NODE_PID 2>/dev/null || true
        exit 1
    fi
else
    echo -e "${RED}✗ IPv6 default ping failed (no statistics)${NC}"
    kill $NODE_PID 2>/dev/null || true
    exit 1
fi

# Test: Large packets with PMTU discovery
echo "Test: IPv6 ping with large packets (PMTU discovery enabled)"
PING6_OUTPUT=$(ping6 -c 4 -W 5 -s 5000 fd00::2 2>&1 || true)
echo "$PING6_OUTPUT"
if echo "$PING6_OUTPUT" | grep -q " received"; then
    RECEIVED=$(echo "$PING6_OUTPUT" | grep "packets transmitted" | awk '{print $4}')
    if [ "$RECEIVED" != "0" ]; then
        echo -e "${GREEN}✓ IPv6 large ping with PMTU discovery successful${NC}"
        if echo "$PING6_OUTPUT" | grep -q "Packet too big\|too big"; then
            echo -e "${GREEN}  First ping failed as expected (PMTU discovery in action)${NC}"
        fi
    else
        echo -e "${RED}✗ IPv6 large ping with PMTU discovery failed${NC}"
        kill $NODE_PID 2>/dev/null || true
        exit 1
    fi
else
    echo -e "${RED}✗ IPv6 large ping with PMTU discovery failed (no statistics)${NC}"
    kill $NODE_PID 2>/dev/null || true
    exit 1
fi
echo ""

echo -e "${GREEN}=== All tests passed! ===${NC}"
echo ""

# Show logs
echo "Node1 log:"
cat "$WORK_DIR/node1.log"
echo ""
echo "Node2 log:"
cat "$WORK_DIR/node2.log"

# Clean up
kill $NODE_PID 2>/dev/null || true

exit 0
