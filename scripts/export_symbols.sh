#!/usr/bin/env bash
# export_symbols.sh — List all exported public symbols from a shared library.
#
# Usage:
#   bash export_symbols.sh <library.so>
#
# Output: one symbol per line, sorted alphabetically.
# Filters to TEXT (T) symbols only — these are the callable functions.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <library.so>" >&2
    exit 1
fi

LIB="$1"

if [ ! -f "$LIB" ]; then
    echo "Error: file not found: $LIB" >&2
    exit 1
fi

echo "=== Exported functions in $LIB ==="
nm -D "$LIB" | grep ' T ' | awk '{print $3}' | sort

echo ""
echo "Total: $(nm -D "$LIB" | grep -c ' T ')"
