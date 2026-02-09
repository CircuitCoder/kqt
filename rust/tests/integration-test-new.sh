#!/bin/bash
# Legacy integration test wrapper
# This script provides backward compatibility by calling the new test infrastructure

set -e

# Colors for output
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${YELLOW}================================================${NC}"
echo -e "${YELLOW}  Legacy Integration Test (Backward Compatible)${NC}"
echo -e "${YELLOW}================================================${NC}"
echo ""
echo -e "${BLUE}Note: This script is a wrapper for the new modular test infrastructure.${NC}"
echo -e "${BLUE}The new tests are located in: rust/test/${NC}"
echo ""
echo -e "${BLUE}Running new test infrastructure...${NC}"
echo ""

# Run the new test runner
cd "$SCRIPT_DIR/../test"
exec bash run-all.sh
