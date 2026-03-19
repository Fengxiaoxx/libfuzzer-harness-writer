#!/usr/bin/env bash
# compile_fuzz.sh — Compile a single LibFuzzer harness with ASan.
#
# Usage:
#   bash compile_fuzz.sh <harness.c> <library.a> <include_dir> <output_binary>
#
# Requirements: clang with libFuzzer support (typically clang 6+)
#
# The harness is compiled with:
#   -fsanitize=fuzzer,address  (LibFuzzer + AddressSanitizer)
#   -O1                        (enough optimisation to keep throughput high,
#                               low enough to preserve debug info)
#   -g                         (debug symbols for readable crash stacks)
#   -Wall -Wextra -Werror      (zero-warning policy)

set -euo pipefail

if [ $# -lt 4 ]; then
    echo "Usage: $0 <harness.c> <library.a> <include_dir> <output_binary>" >&2
    exit 1
fi

HARNESS="$1"
LIB="$2"
INCLUDE_DIR="$3"
OUTPUT="$4"

echo "Compiling $HARNESS ..."
clang \
    -fsanitize=fuzzer,address \
    -O1 \
    -g \
    -Wall -Wextra -Werror \
    "$HARNESS" \
    "$LIB" \
    -I"$INCLUDE_DIR" \
    -o "$OUTPUT"

echo "OK: $OUTPUT"
