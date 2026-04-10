#!/bin/bash
set -e

echo "=========================================="
echo "Running Local CI Pipeline"
echo "=========================================="

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FAILED=0

# Function to run a test and report results
run_test() {
    local name=$1
    local cmd=$2

    echo -e "\n${YELLOW}[TEST]${NC} $name"
    echo "Command: $cmd"
    echo "---"

    if eval "$cmd"; then
        echo -e "${GREEN}✓ PASS${NC}: $name"
    else
        echo -e "${RED}✗ FAIL${NC}: $name"
        FAILED=$((FAILED + 1))
    fi
}

# Lint Job
echo -e "\n${YELLOW}====== LINT JOB ======${NC}"
run_test "go vet" "go vet ./..."
run_test "golangci-lint" "golangci-lint run ./..."

# Test Job
echo -e "\n${YELLOW}====== TEST JOB ======${NC}"
run_test "go build" "go build ./..."

run_test "unit tests (race + coverage)" \
    "ginkgo -r \
      --race \
      --cover \
      --coverprofile=coverage.out \
      --covermode=atomic \
      --coverpkg=./... \
      --skip-package=integration \
      pkg/keymanager pkg/tokens pkg/storage pkg/logging pkg/metrics"

run_test "integration tests — disk + memory + Redis distributed (miniredis)" \
    "ginkgo -r --race --timeout=180s --randomize-all --tags=integration ./pkg/tokens/integration/..."

# Coverage report
echo -e "\n${YELLOW}[INFO]${NC} Generating coverage report..."
go tool cover -html=coverage.out -o coverage.html
echo -e "${GREEN}✓${NC} Coverage HTML saved to coverage.html"

# Summary
echo -e "\n${YELLOW}=========================================="
echo "CI Pipeline Summary"
echo "==========================================${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL CHECKS PASSED${NC}"
    exit 0
else
    echo -e "${RED}✗ $FAILED CHECK(S) FAILED${NC}"
    exit 1
fi
