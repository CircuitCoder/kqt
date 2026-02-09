#!/bin/bash
# Main test runner - runs all test suites

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  KQT Integration Test Suite Runner  ${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Track test results
PASSED=0
FAILED=0
TOTAL=0

# Function to run a test suite
run_test() {
    local test_name="$1"
    local test_script="$2"
    
    TOTAL=$((TOTAL + 1))
    echo -e "${BLUE}[$TOTAL] Running: $test_name${NC}"
    echo ""
    
    if bash "$test_script"; then
        echo ""
        echo -e "${GREEN}✓ $test_name passed${NC}"
        echo ""
        PASSED=$((PASSED + 1))
        return 0
    else
        echo ""
        echo -e "${RED}✗ $test_name failed${NC}"
        echo ""
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# Run all test suites
echo -e "${YELLOW}Starting test suites...${NC}"
echo ""

# L2 connectivity test
run_test "L2 Connectivity Test" "$SCRIPT_DIR/l2/run.sh" || true

# L3 connectivity test
run_test "L3 Connectivity Test" "$SCRIPT_DIR/l3/run.sh" || true

# L2-L3 incompatibility test
run_test "L2-L3 Incompatibility Test" "$SCRIPT_DIR/l2-l3-incompatible/run.sh" || true

# Print summary
echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo -e "Total tests:  $TOTAL"
echo -e "${GREEN}Passed:       $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed:       $FAILED${NC}"
else
    echo -e "Failed:       $FAILED"
fi
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
