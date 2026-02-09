#!/bin/bash
# L2-L3 incompatibility test script
# Tests that L2 tunnel should not connect to L3 tunnel
# Runs in the context of node1's network namespace

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== L2-L3 Incompatibility Test ===${NC}"
echo ""

# Step 1: Check TUN/TAP device creation
echo -e "${YELLOW}Test 1: Checking TUN/TAP device creation...${NC}"

if ip link show kqt0 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ TUN device kqt0 created in this namespace (L2 mode)${NC}"
else
    echo -e "${RED}✗ TUN device kqt0 not found${NC}"
    exit 1
fi

if sudo ip netns exec "$NS2" ip link show kqt0 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ TUN device kqt0 created in $NS2 (L3 mode)${NC}"
else
    echo -e "${RED}✗ TUN device kqt0 not found in $NS2${NC}"
    exit 1
fi
echo ""

# Wait for connection attempts
echo "Waiting for connection attempts..."
sleep 8
echo ""

# Step 2: Verify nodes are still running by checking TUN devices still exist
echo -e "${YELLOW}Test 2: Verifying nodes are still running...${NC}"

if ip link show kqt0 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Node 1 still running (TUN device exists)${NC}"
else
    echo -e "${RED}✗ Node 1 appears to have exited${NC}"
    exit 1
fi

if sudo ip netns exec "$NS2" ip link show kqt0 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Node 2 still running (TUN device exists)${NC}"
else
    echo -e "${RED}✗ Node 2 appears to have exited${NC}"
    exit 1
fi
echo ""

# Step 3: Verify that connectivity does NOT work
echo -e "${YELLOW}Test 3: Verifying that connectivity does NOT work (expected)...${NC}"

# Try to ping - this should fail
PING_OUTPUT=$(ping -c 2 -W 3 10.21.0.2 2>&1 || true)
echo "$PING_OUTPUT"

if echo "$PING_OUTPUT" | grep -q " received"; then
    RECEIVED=$(echo "$PING_OUTPUT" | grep "packets transmitted" | awk '{print $4}')
    if [ "$RECEIVED" = "0" ]; then
        echo -e "${GREEN}✓ Ping correctly failed (L2 and L3 modes are incompatible)${NC}"
    else
        echo -e "${RED}✗ Ping succeeded unexpectedly - L2 and L3 should not connect!${NC}"
        exit 1
    fi
else
    # No statistics means ping completely failed (also expected)
    echo -e "${GREEN}✓ Ping correctly failed (L2 and L3 modes are incompatible)${NC}"
fi
echo ""

echo -e "${GREEN}=== L2-L3 incompatibility test passed! ===${NC}"
echo -e "${GREEN}Nodes stayed running but did not establish connectivity (expected behavior)${NC}"
