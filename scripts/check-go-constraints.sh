#!/usr/bin/env bash
# Validates two Go module constraints for jwtauth:
#   1. Every example module directory contains a go.mod (prevents root module contamination).
#   2. The root go directive does not exceed the minimum version required by ./pkg/... dependencies.
#
# GO_FLOOR is the single source of truth. Bumping it requires an intentional, documented
# change tied to a dependency in ./pkg/... that genuinely requires a higher Go version.
set -euo pipefail

GO_FLOOR="1.25.0"  # Set by go.opentelemetry.io/otel v1.43.0; do not raise without updating this comment.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

ERRORS=0

# ===== CHECK 1: Every example module directory must have its own go.mod =====
echo "Checking example module isolation..."
while IFS= read -r mainfile; do
    dir="$(dirname "$mainfile")"
    if [[ ! -f "$dir/go.mod" ]]; then
        echo "  FAIL: $dir has Go files but no go.mod — add one to isolate it from the root module"
        ERRORS=$((ERRORS + 1))
    fi
done < <(find examples/ -name "main.go" | sort)

if [[ $ERRORS -eq 0 ]]; then
    echo "  OK: all example directories are isolated modules"
fi

# ===== CHECK 2: Root go directive must not exceed the floor =====
echo "Checking root go directive floor..."
current=$(grep '^go ' go.mod | awk '{print $2}')
if [[ "$(printf '%s\n' "$GO_FLOOR" "$current" | sort -V | tail -1)" != "$GO_FLOOR" ]]; then
    echo "  FAIL: root go directive is $current, exceeds floor $GO_FLOOR"
    echo "        Raising the floor requires an intentional, documented change — update GO_FLOOR"
    echo "        in scripts/check-go-constraints.sh and note which ./pkg/... dependency requires it."
    ERRORS=$((ERRORS + 1))
else
    echo "  OK: root go directive ($current) is within floor ($GO_FLOOR)"
fi

if [[ $ERRORS -gt 0 ]]; then
    exit 1
fi
