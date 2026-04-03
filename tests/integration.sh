#!/bin/bash
# Integration test for procfast
# Run as root: sudo ./tests/integration.sh
set -e

PROCFASTD=./target/release/procfastd
PROCFAST=./target/release/procfast
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

check() {
    local desc="$1"
    local cmd="$2"
    local expect="$3"
    local result
    result=$(eval "$cmd" 2>/dev/null) || true
    if echo "$result" | grep -qE "$expect"; then
        pass "$desc"
    else
        fail "$desc (expected /$expect/, got: $(echo "$result" | head -1))"
    fi
}

echo "=== Starting procfastd --fd ==="
$PROCFASTD --fd &
DAEMON_PID=$!
sleep 3

if ! $PROCFAST status >/dev/null 2>&1; then
    echo "FATAL: procfastd failed to start"
    kill $DAEMON_PID 2>/dev/null
    exit 1
fi
echo "  procfastd running (pid $DAEMON_PID)"

echo ""
echo "=== Collector tests ==="

check "CPU: nr_cpus > 0" \
    "$PROCFAST cpu | head -1" \
    "CPU Statistics \([0-9]+ CPUs\)"

check "CPU: shows per-core data" \
    "$PROCFAST cpu | grep '^ *0'" \
    "[0-9]+\.[0-9]+%"

check "Memory: total > 0" \
    "$PROCFAST mem | grep Total" \
    "Total:.*[0-9]+ MiB"

check "Memory: free > 0" \
    "$PROCFAST mem | grep Free" \
    "Free:.*[0-9]+ MiB"

check "Network: shows interfaces" \
    "$PROCFAST net | grep -v '^Interface' | grep -v '^-'" \
    "[a-z].*[0-9]"

check "Disk: shows devices" \
    "$PROCFAST disk" \
    "Device"

check "IRQ: shows interrupts" \
    "$PROCFAST irq | head -3" \
    "CPU[0-9]"

check "Thermal: collector loaded" \
    "$PROCFAST status" \
    "running"

check "Process list: > 100 processes" \
    "$PROCFAST ps | head -3" \
    "Processes: [0-9]+ tracked"

check "Process: PID 1 exists" \
    "$PROCFAST pid 1" \
    "Process 1"

check "FD: shows open files" \
    "$PROCFAST fd | wc -l" \
    "[0-9]{3,}"

check "Socket: shows connections" \
    "$PROCFAST sock | grep -c tcp" \
    "[0-9]+"

echo ""
echo "=== Output format tests ==="

check "JSON cpu" \
    "$PROCFAST json cpu | head -1" \
    "^\{"

check "JSON mem" \
    "$PROCFAST json mem | head -1" \
    "^\{"

check "JSON ps" \
    "$PROCFAST json ps | head -1" \
    "^\{"

check "JSON sock" \
    "$PROCFAST json sock | head -1" \
    "^\{"

check "Top: shows header" \
    "$PROCFAST top 2>&1 | head -1" \
    "procfast top"

echo ""
echo "=== Benchmark test ==="

check "Benchmark runs" \
    "./target/release/procfast-bench -n 100 cpu 2>/dev/null | grep 'faster'" \
    "[0-9]+x faster"

echo ""
echo "=== Cleanup ==="
kill $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null || true
echo "  procfastd stopped"

echo ""
echo "========================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================="

[ $FAIL -eq 0 ] && exit 0 || exit 1
