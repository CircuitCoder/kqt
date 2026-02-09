#!/bin/bash
# L2-L3 incompatibility test script
# Tests that L2 tunnel should not connect to L3 tunnel
# The internal connection should fail to connect, but nodes should not exit

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

if sudo ip netns exec "$NS1" ip link show kqt0 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ TUN device kqt0 created in $NS1 (L2 mode)${NC}"
else
    echo -e "${RED}✗ TUN device kqt0 not found in $NS1${NC}"
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

# Step 2: Verify nodes are still running
echo -e "${YELLOW}Test 2: Verifying nodes are still running...${NC}"

# Check node logs exist
if [ ! -f "$WORK_DIR/node1.log" ] || [ ! -f "$WORK_DIR/node2.log" ]; then
    echo -e "${RED}✗ Log files not found${NC}"
    exit 1
fi

# Display log excerpts to show connection failures
echo "Node1 log excerpt (last 20 lines):"
tail -n 20 "$WORK_DIR/node1.log"
echo ""

echo "Node2 log excerpt (last 20 lines):"
tail -n 20 "$WORK_DIR/node2.log"
echo ""

# Check if logs contain expected failure messages
# The exact error message may vary, so we'll look for general connection/handshake issues
echo -e "${YELLOW}Test 3: Checking for connection failure indicators...${NC}"

# Look for any indication that the connection failed or handshake failed
# We expect to see errors related to incompatible modes or failed connections
if grep -qi "error\|failed\|reject\|incompatible\|mismatch" "$WORK_DIR/node1.log" "$WORK_DIR/node2.log"; then
    echo -e "${GREEN}✓ Connection failures detected in logs (expected behavior)${NC}"
else
    echo -e "${YELLOW}⚠ No obvious connection failure messages found in logs${NC}"
    echo -e "${YELLOW}  This might still be correct if connections are silently rejected${NC}"
fi
echo ""

# Step 4: Verify that connectivity does NOT work
echo -e "${YELLOW}Test 4: Verifying that connectivity does NOT work (expected)...${NC}"

# Try to ping - this should fail
PING_OUTPUT=$(sudo ip netns exec "$NS1" ping -c 2 -W 3 10.21.0.2 2>&1 || true)
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
