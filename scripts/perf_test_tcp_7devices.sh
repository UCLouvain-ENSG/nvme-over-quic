#!/usr/bin/env bash
# SPDK NVMe-oF TCP Performance Test - 7 Devices (matching official test methodology)
# Tests all 7 subsystems simultaneously like official 14-device test

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPDK_DIR="$SCRIPT_DIR/.."
PERF_BIN="$SPDK_DIR/build/bin/spdk_nvme_perf"

# Test parameters (can be overridden with environment variables)
QUEUE_DEPTH="${QUEUE_DEPTH:-384}"
BLOCK_SIZE="${BLOCK_SIZE:-4096}"
WORKLOAD="${WORKLOAD:-randread}"
RUNTIME="${RUNTIME:-10}"
COREMASK="${COREMASK:-0xF}"  # 4 cores by default

# Target configuration
TARGET_ADDR="${TARGET_ADDR:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-4420}"

echo "=========================================="
echo "SPDK TCP Performance Test - 7 Devices"
echo "Matching official test methodology"
echo "=========================================="
echo ""
echo "Test Configuration:"
echo "  Devices:      7 NULL bdevs (simultaneous)"
echo "  Queue Depth:  $QUEUE_DEPTH"
echo "  Block Size:   $BLOCK_SIZE bytes ($(($BLOCK_SIZE/1024))KB)"
echo "  Workload:     $WORKLOAD"
echo "  Runtime:      ${RUNTIME}s"
echo "  CPU Coremask: $COREMASK"
echo "  Target:       $TARGET_ADDR:$TARGET_PORT"
echo ""

# Check if perf binary exists
if [ ! -f "$PERF_BIN" ]; then
    echo "ERROR: spdk_nvme_perf not found at $PERF_BIN"
    exit 1
fi

# Verify subsystems exist (need at least 7)
echo "Verifying subsystems..."
SUBSYSTEMS=$(sudo "$SPDK_DIR/scripts/rpc.py" nvmf_get_subsystems 2>/dev/null | \
    jq -r '.[].nqn' | grep "^nqn.2018-09.io.spdk:cnode" || true)

NUM_SUBSYSTEMS=$(echo "$SUBSYSTEMS" | wc -l)
if [ $NUM_SUBSYSTEMS -lt 7 ]; then
    echo "ERROR: Need at least 7 subsystems, found $NUM_SUBSYSTEMS"
    echo "Run ./setup_tcp_perf_target.sh first"
    exit 1
fi

# Use only the first 7 subsystems
SUBSYSTEMS=$(echo "$SUBSYSTEMS" | head -7)
echo "✓ Found $NUM_SUBSYSTEMS subsystems, using first 7:"
echo "$SUBSYSTEMS" | sed 's/^/  /'
echo ""

# Build the command with 7 -r flags
CMD="sudo $PERF_BIN \
    -q $QUEUE_DEPTH \
    -o $BLOCK_SIZE \
    -w $WORKLOAD \
    -t $RUNTIME \
    -c $COREMASK \
    -S posix \
    -r 'trtype:TCP adrfam:IPv4 traddr:$TARGET_ADDR trsvcid:$TARGET_PORT subnqn:nqn.2018-09.io.spdk:cnode1' \
    -r 'trtype:TCP adrfam:IPv4 traddr:$TARGET_ADDR trsvcid:$TARGET_PORT subnqn:nqn.2018-09.io.spdk:cnode2' \
    -r 'trtype:TCP adrfam:IPv4 traddr:$TARGET_ADDR trsvcid:$TARGET_PORT subnqn:nqn.2018-09.io.spdk:cnode3' \
    -r 'trtype:TCP adrfam:IPv4 traddr:$TARGET_ADDR trsvcid:$TARGET_PORT subnqn:nqn.2018-09.io.spdk:cnode4' \
    -r 'trtype:TCP adrfam:IPv4 traddr:$TARGET_ADDR trsvcid:$TARGET_PORT subnqn:nqn.2018-09.io.spdk:cnode5' \
    -r 'trtype:TCP adrfam:IPv4 traddr:$TARGET_ADDR trsvcid:$TARGET_PORT subnqn:nqn.2018-09.io.spdk:cnode6' \
    -r 'trtype:TCP adrfam:IPv4 traddr:$TARGET_ADDR trsvcid:$TARGET_PORT subnqn:nqn.2018-09.io.spdk:cnode7'"

echo "Running command:"
echo "sudo spdk_nvme_perf \\"
echo "  -q $QUEUE_DEPTH -o $BLOCK_SIZE -w $WORKLOAD -t $RUNTIME -c $COREMASK -S posix \\"
for i in {1..7}; do
    echo "  -r 'trtype:TCP ... subnqn:nqn.2018-09.io.spdk:cnode$i' \\"
done | sed '$ s/ \\$//'
echo ""
echo "Test starting (${RUNTIME}s runtime)..."
echo "=========================================="
echo ""

# Run the test
eval $CMD

EXIT_CODE=$?

echo ""
echo "=========================================="
if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ Test complete!"
else
    echo "✗ Test failed with exit code $EXIT_CODE"
fi
echo "=========================================="
echo ""
echo "Test Variations:"
echo ""
echo "Queue Depth (from official benchmark):"
echo "  QUEUE_DEPTH=128 $0  # Low"
echo "  QUEUE_DEPTH=256 $0  # Medium"
echo "  QUEUE_DEPTH=384 $0  # High"
echo ""
echo "Workload:"
echo "  WORKLOAD=randread $0   # 100% read (default)"
echo "  WORKLOAD=randwrite $0  # 100% write"
echo "  WORKLOAD=randrw $0     # Mixed read/write"
echo ""
echo "Block Size:"
echo "  BLOCK_SIZE=4096 $0     # 4KB (default)"
echo "  BLOCK_SIZE=8192 $0     # 8KB"
echo "  BLOCK_SIZE=131072 $0   # 128KB (matches official)"
echo ""
echo "CPU Cores:"
echo "  COREMASK=0x1 $0        # 1 core"
echo "  COREMASK=0xF $0        # 4 cores (default)"
echo "  COREMASK=0xFF $0       # 8 cores"
echo ""
echo "Quick test:"
echo "  RUNTIME=60 $0"
echo ""
echo "Combined (official test equivalent):"
echo "  QUEUE_DEPTH=128 BLOCK_SIZE=4096 RUNTIME=300 COREMASK=0xF $0"
echo ""

exit $EXIT_CODE
