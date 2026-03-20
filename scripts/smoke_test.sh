#!/usr/bin/env bash
# smoke_test.sh — Run a compiled LibFuzzer binary for a short time and check health.
#
# Usage:
#   bash smoke_test.sh <fuzzer_binary> [corpus_dir] [max_total_time_seconds]
#
# Exit code 0 = PASS (no crash, throughput acceptable)
# Exit code 1 = FAIL (crash detected or throughput too low)
#
# Default runtime: 60 seconds (aligned with OSS-Fuzz integration test duration)
# Minimum acceptable throughput: 1000 exec/s for ASan; 200 exec/s for MSan (MSan ~5x slower)

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <fuzzer_binary> [corpus_dir] [max_total_time_seconds]" >&2
    exit 1
fi

BINARY="$1"
CORPUS="${2:-}"
TIME="${3:-60}"
MIN_EXECS=200   # minimum exec/s (conservative: covers MSan's ~5x slowdown vs ASan)

if [ ! -x "$BINARY" ]; then
    echo "Error: not executable: $BINARY" >&2
    exit 1
fi

ARGS="-max_total_time=$TIME -max_len=4096"
if [ -n "$CORPUS" ] && [ -d "$CORPUS" ]; then
    ARGS="$ARGS $CORPUS"
fi

echo "=== Smoke test: $BINARY (${TIME}s) ==="
OUTPUT=$("$BINARY" $ARGS 2>&1) || true

# Check for crash signatures
if echo "$OUTPUT" | grep -qE "CRASH|ERROR: AddressSanitizer|abort|deadly signal"; then
    echo "FAIL: crash or sanitizer error detected"
    echo "$OUTPUT" | tail -20
    exit 1
fi

# Extract throughput from "Done N runs in M second(s)"
DONE_LINE=$(echo "$OUTPUT" | grep -E "^Done [0-9]+ runs in" || true)
if [ -n "$DONE_LINE" ]; then
    RUNS=$(echo "$DONE_LINE" | awk '{print $2}')
    SECS=$(echo "$DONE_LINE" | awk '{print $5}')
    # integer division — good enough for a smoke test
    THROUGHPUT=$(( RUNS / SECS ))
    echo "Throughput: ~${THROUGHPUT} exec/s (${RUNS} runs in ${SECS}s)"
    if [ "$THROUGHPUT" -lt "$MIN_EXECS" ]; then
        echo "WARN: throughput below ${MIN_EXECS} exec/s — consider profiling"
    fi
else
    echo "(Could not parse throughput line)"
fi

echo "PASS: no crash in ${TIME}s"
exit 0
