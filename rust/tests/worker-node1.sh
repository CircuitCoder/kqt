#!/bin/bash
# Worker script for worker 1 (runs node2 as server only)
# This script runs inside a network namespace created by kqt-tester
# KQT_TESTER_NODE environment variable is set to 1

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

echo -e "${YELLOW}Worker 1 (running node2) starting in network namespace...${NC}"

# Start kqt node2 in background
"$KQT_BIN" server "$WORK_DIR/node2.toml" kqt0 > "$WORK_DIR/node2.log" 2>&1 &
NODE_PID=$!

# Give the node time to start up
sleep 5

# Check if TUN device was created
if ! ip link show kqt0 > /dev/null 2>&1; then
    echo -e "${RED}✗ TUN device kqt0 not found${NC}"
    echo "Node2 log:"
    cat "$WORK_DIR/node2.log"
    kill $NODE_PID 2>/dev/null || true
    exit 1
fi

echo -e "${GREEN}✓ TUN device kqt0 created in worker 1 (node2)${NC}"

# Wait for up to 30 seconds for the test to complete
echo "Worker 1 waiting for tests to complete (up to 30 seconds)..."
for i in {1..30}; do
    if ! kill -0 $NODE_PID 2>/dev/null; then
        echo "KQT process exited"
        break
    fi
    sleep 1
done

# Clean up
kill $NODE_PID 2>/dev/null || true

exit 0
