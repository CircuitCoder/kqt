#!/bin/bash
# Integration test for kqt using kqt-tester
# This script uses the kqt-tester utility to set up network namespaces

set -e

# Configuration
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${WORK_DIR:-$TEST_DIR/run}"
KQT_BIN="${KQT_BIN:-$TEST_DIR/../target/release/kqt}"
KQT_TESTER_BIN="${KQT_TESTER_BIN:-$TEST_DIR/../target/release/kqt-tester}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== KQT Integration Test (using kqt-tester) ==="
echo ""

# Check if kqt binary exists
if [ ! -f "$KQT_BIN" ]; then
    echo -e "${RED}Error: kqt binary not found at $KQT_BIN${NC}"
    echo "Please build the project first with: cd rust && cargo build --release"
    exit 1
fi

# Check if kqt-tester binary exists
if [ ! -f "$KQT_TESTER_BIN" ]; then
    echo -e "${RED}Error: kqt-tester binary not found at $KQT_TESTER_BIN${NC}"
    echo "Please build the project first with: cd rust && cargo build --release"
    exit 1
fi

# Check if kqt binary is executable
if [ ! -x "$KQT_BIN" ]; then
    echo -e "${RED}Error: kqt binary at $KQT_BIN is not executable${NC}"
    exit 1
fi

# Check if kqt-tester binary is executable
if [ ! -x "$KQT_TESTER_BIN" ]; then
    echo -e "${RED}Error: kqt-tester binary at $KQT_TESTER_BIN is not executable${NC}"
    exit 1
fi

# Create working directory
mkdir -p "$WORK_DIR"
cd "$TEST_DIR"

# Step 1: Generate keys (if not already present)
if [ ! -f "$WORK_DIR/ca-private.txt" ]; then
    echo -e "${YELLOW}Step 1: Generating CA and keypairs...${NC}"
    bash generate-keys.sh "$WORK_DIR"
    echo ""
else
    echo -e "${YELLOW}Step 1: Using existing CA and keypairs...${NC}"
    echo ""
fi

# Step 2: Generate configs (if not already present)
if [ ! -f "$WORK_DIR/node1.toml" ]; then
    echo -e "${YELLOW}Step 2: Generating configuration files...${NC}"
    bash generate-configs.sh "$WORK_DIR"
    echo ""
else
    echo -e "${YELLOW}Step 2: Using existing configuration files...${NC}"
    echo ""
fi

# Step 3: Run tests using kqt-tester
echo -e "${YELLOW}Step 3: Running tests in network namespaces using kqt-tester...${NC}"
export WORK_DIR
export KQT_BIN

# Run kqt-tester with worker scripts (worker 0 runs tests, worker 1 runs server)
"$KQT_TESTER_BIN" "$TEST_DIR/worker-node0.sh" "$TEST_DIR/worker-node1.sh"

echo -e "${GREEN}Integration test completed successfully!${NC}"
