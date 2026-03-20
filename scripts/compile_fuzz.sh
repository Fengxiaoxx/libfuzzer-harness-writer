#!/usr/bin/env bash
# compile_fuzz.sh — Compile a single LibFuzzer harness against an instrumented library.
#
# Usage:
#   bash compile_fuzz.sh <sanitizer> <harness.c> <library.a> <include_dir> <output_binary>
#
#   sanitizer: asan | msan
#
# Example (both builds, matching build_harness/ layout from libfuzzer-lib-builder):
#   bash compile_fuzz.sh asan harness.c build_harness/asan/libfoo.a build_harness/asan/include /tmp/harness_asan
#   bash compile_fuzz.sh msan harness.c build_harness/msan/libfoo.a build_harness/msan/include /tmp/harness_msan
#
# Requirements: clang with libFuzzer support (clang 6+)
#
# Flags used:
#   -fsanitize=fuzzer,address|memory  LibFuzzer engine + sanitizer
#   -O1 -g                            balance throughput vs. debug info
#   -Wall -Wextra -Werror             zero-warning policy
#   -fsanitize-memory-track-origins   (msan only) show allocation site in reports

set -euo pipefail

if [ $# -lt 5 ]; then
    echo "Usage: $0 <asan|msan> <harness.c> <library.a> <include_dir> <output_binary>" >&2
    exit 1
fi

SANITIZER="$1"
HARNESS="$2"
LIB="$3"
INCLUDE_DIR="$4"
OUTPUT="$5"

case "$SANITIZER" in
    asan)
        SAN_FLAGS="-fsanitize=fuzzer,address"
        ;;
    msan)
        # -fsanitize-memory-track-origins: when MSan fires, prints where the
        # uninitialized bytes were allocated — essential for root-cause analysis.
        SAN_FLAGS="-fsanitize=fuzzer,memory -fsanitize-memory-track-origins"
        ;;
    *)
        echo "Unknown sanitizer '$SANITIZER'. Use 'asan' or 'msan'." >&2
        exit 1
        ;;
esac

# Choose compiler based on file extension.
# clang++ applies C++ name mangling to LLVMFuzzerTestOneInput in .c files,
# causing "undefined reference" link errors — always use clang for .c harnesses.
case "$HARNESS" in
    *.cpp|*.cc|*.cxx) COMPILER=clang++ ;;
    *)                COMPILER=clang   ;;
esac

echo "Compiling [$SANITIZER] $HARNESS ..."
$COMPILER \
    $SAN_FLAGS \
    -O1 \
    -g \
    -Wall -Wextra -Werror \
    "$HARNESS" \
    "$LIB" \
    -I"$INCLUDE_DIR" \
    -o "$OUTPUT"

echo "OK: $OUTPUT"
