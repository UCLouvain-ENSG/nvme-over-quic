#!/usr/bin/env bash
# Run SPDK NVMe-oF TCP Performance Tests using spdk_nvme_perf
# Alternative to FIO-based testing (no FIO plugin needed)

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPDK_DIR="$SCRIPT_DIR/.."
PERF_BIN="$SPDK_DIR/build/bin/spdk_nvme_perf"

# Test parameters
QUEUE_DEPTH="${QUEUE_DEPTH:-128}"
BLOCK_SIZE="${BLOCK_SIZE:-4096}"
WORKLOAD="${WORKLOAD:-randread}"
RUNTIME="${RUNTIME:-300}"
COREMASK="${COREMASK:-0x1}"  # 0x1 = core 0, 0xF = cores 0-3

# Target configuration
TARGET_ADDR="${TARGET_ADDR:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-4420}"
SUBNQN_BASE="nqn.2018-09.io.spdk:cnode"

echo "=========================================="
echo "SPDK NVMe-oF TCP Performance Test"
echo "Using spdk_nvme_perf"
echo "=========================================="
echo ""
echo "Test Configuration:"
echo "  Queue Depth:  $QUEUE_DEPTH"
echo "  Block Size:   $BLOCK_SIZE bytes"
echo "  Workload:     $WORKLOAD"
echo "  Runtime:      ${RUNTIME}s"
echo "  CPU Coremask: $COREMASK"
echo "  Target:       $TARGET_ADDR:$TARGET_PORT"
echo ""

# Check if perf binary exists
if [ ! -f "$PERF_BIN" ]; then
    echo "ERROR: spdk_nvme_perf not found at $PERF_BIN"
    echo "Build it with: cd $SPDK_DIR && make"
    exit 1
fi

# Determine available subsystems
echo "Detecting available subsystems..."
SUBSYSTEMS=$(sudo "$SPDK_DIR/scripts/rpc.py" nvmf_get_subsystems 2>/dev/null | \
    jq -r '.[].nqn' | grep "^nqn.2018-09.io.spdk:cnode" || true)

if [ -z "$SUBSYSTEMS" ]; then
    echo "ERROR: No subsystems found!"
    echo "Make sure the target is running and configured."
    echo "Run: ./setup_tcp_perf_target.sh"
    exit 1
fi

NUM_SUBSYSTEMS=$(echo "$SUBSYSTEMS" | wc -l)
echo "Found $NUM_SUBSYSTEMS subsystem(s):"
echo "$SUBSYSTEMS" | sed 's/^/  - /'
echo ""

# Build transport string for all subsystems
TRANSPORT_ARGS=""
for subnqn in $SUBSYSTEMS; do
    TRANSPORT_ARGS="$TRANSPORT_ARGS -r 'trtype:TCP adrfam:IPv4 traddr:$TARGET_ADDR trsvcid:$TARGET_PORT subnqn:$subnqn'"
done

# Create the full command
CMD="sudo $PERF_BIN \
    -q $QUEUE_DEPTH \
    -o $BLOCK_SIZE \
    -w $WORKLOAD \
    -t $RUNTIME \
    -c $COREMASK \
    -S posix \
    $TRANSPORT_ARGS"

echo "Running command:"
echo "$CMD" | sed 's/ -r /\n  -r /g'
echo ""
echo "Socket implementation: POSIX (TCP)"
echo ""
echo "Test starting..."
echo "=========================================="
echo ""

# Run the test (environment variable is already in CMD)
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
echo "To run with different parameters:"
echo "  QUEUE_DEPTH=256 WORKLOAD=randwrite $0"
echo ""
echo "Queue depth tests (from official benchmark):"
echo "  QUEUE_DEPTH=128 $0"
echo "  QUEUE_DEPTH=256 $0"
echo "  QUEUE_DEPTH=384 $0"
echo ""
echo "Workload tests:"
echo "  WORKLOAD=randread $0    # 100% read"
echo "  WORKLOAD=randwrite $0   # 100% write"
echo "  WORKLOAD=randrw $0      # Mixed read/write"
echo ""
echo "Block size tests:"
echo "  BLOCK_SIZE=4096 $0      # 4KB"
echo "  BLOCK_SIZE=8192 $0      # 8KB"
echo "  BLOCK_SIZE=131072 $0    # 128KB"
echo ""
echo "CPU core tests:"
echo "  COREMASK=0x1 $0         # Single core (core 0)"
echo "  COREMASK=0xF $0         # 4 cores (cores 0-3)"
echo "  COREMASK=0xFF $0        # 8 cores (cores 0-7)"
echo ""
echo "Quick test:"
echo "  RUNTIME=60 $0"
echo ""

exit $EXIT_CODE
