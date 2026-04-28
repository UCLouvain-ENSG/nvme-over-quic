#!/usr/bin/env bash
# SPDK NVMe-oF TCP Target Setup - Matching Official Performance Test
# Based on SPDK NVMe-oF TCP Performance Report (Release 24.0)

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPDK_DIR="$SCRIPT_DIR/.."
RPC="$SPDK_DIR/scripts/rpc.py"

# Configuration
SUBNQN_BASE="nqn.2018-09.io.spdk:cnode"
LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1}"
LISTEN_PORT=4420

echo "=========================================="
echo "SPDK NVMe-oF TCP Performance Target Setup"
echo "=========================================="
echo ""

# Step 1: Set default socket implementation to POSIX (TCP)
echo "[1/7] Setting socket implementation to POSIX..."
$RPC sock_set_default_impl -i posix
echo "  ✓ Socket implementation: posix (TCP)"

# Step 2: Set iobuf buffer pool options (from official test)
echo "[2/7] Setting iobuf buffer pool options..."
$RPC iobuf_set_options --small-pool-count 32767 --large-pool-count 16383
echo "  ✓ Small pool: 32767, Large pool: 16383"

# Step 3: Enable zero-copy send on Target side
echo "[3/7] Enabling zero-copy send (server side)..."
$RPC sock_impl_set_options --impl=posix --enable-zerocopy-send-server
echo "  ✓ Zero-copy send enabled"

# Step 4: Initialize framework
echo "[4/7] Starting framework initialization..."
$RPC framework_start_init
echo "  ✓ Framework initialized"

# Step 5: Create TCP transport with official performance parameters
echo "[5/7] Creating TCP transport with performance parameters..."
$RPC nvmf_create_transport -t TCP \
    --max-queue-depth 128 \
    --max-io-qpairs-per-ctrlr 127 \
    --in-capsule-data-size 4096 \
    --max-io-size 131072 \
    --io-unit-size 131072 \
    --max-aq-depth 128 \
    --num-shared-buffers 8192 \
    --buf-cache-size 32 \
    --abort-timeout-sec 1 \
    --c2h-success

echo "  ✓ TCP transport created with:"
echo "    - Max queue depth: 128"
echo "    - Max IO qpairs: 127"
echo "    - IO unit size: 131072 (128KB)"
echo "    - Shared buffers: 8192"
echo "    - C2H success optimization enabled"

# Step 5: Attach NVMe controllers (or create test bdevs)
echo "[5/6] Setting up block devices..."

# Option A: Use physical NVMe drives (uncomment and modify as needed)
# Detect available NVMe devices
# NVME_DEVICES=($(lspci -D | grep -i "Non-Volatile memory controller" | awk '{print $1}'))
# if [ ${#NVME_DEVICES[@]} -eq 0 ]; then
#     echo "  ⚠ No physical NVMe devices found, using malloc bdevs instead"
# else
#     echo "  Found ${#NVME_DEVICES[@]} NVMe device(s)"
#     for i in "${!NVME_DEVICES[@]}"; do
#         ADDR="${NVME_DEVICES[$i]}"
#         echo "  Attaching NVMe$i at $ADDR..."
#         $RPC bdev_nvme_attach_controller -t PCIe -b Nvme$i -a "$ADDR" || true
#     done
# fi

# Option B: Use NVMe partition via AIO (for single device testing)
NVME_PARTITION="/dev/nvme0n1p5"
if [ -b "$NVME_PARTITION" ]; then
    echo "  Using NVMe partition: $NVME_PARTITION"
    if mountpoint -q "$NVME_PARTITION" 2>/dev/null || grep -qs "$NVME_PARTITION" /proc/mounts; then
        echo "  ⚠ Warning: $NVME_PARTITION is mounted, skipping AIO bdev"
    else
        $RPC bdev_aio_create "$NVME_PARTITION" Nvme0n1 || echo "  ⚠ Failed to create AIO bdev"
    fi
fi

# Option C: Create NULL bdevs for testing (no memory/storage overhead)
# NULL bdevs are perfect for performance testing - they discard all writes
NUM_BDEVS=${NUM_BDEVS:-7}
echo "  Creating $NUM_BDEVS NULL bdev(s) for testing (10GB each)..."
for i in $(seq 0 $((NUM_BDEVS-1))); do
    # 10GB = 2621440 blocks * 4096 bytes (no actual memory used)
    $RPC bdev_null_create Null${i} 2621440 4096 || echo "  ⚠ Null$i already exists"
done

# Step 7: Create NVMe-oF subsystems and add namespaces
echo "[7/7] Creating NVMe-oF subsystems..."

# Get list of available bdevs
BDEVS=$($RPC bdev_get_bdevs | jq -r '.[].name' | grep -E '^(Nvme|Null)')

i=1
for bdev in $BDEVS; do
    SUBNQN="${SUBNQN_BASE}${i}"
    SERIAL=$(printf "SPDK%012d" $i)
    
    echo "  Creating subsystem $i: $SUBNQN"
    $RPC nvmf_create_subsystem "$SUBNQN" -s "$SERIAL" -a -m 8 || echo "    ⚠ Subsystem exists"
    
    echo "    Adding namespace: $bdev"
    $RPC nvmf_subsystem_add_ns "$SUBNQN" "$bdev" || echo "    ⚠ Namespace already added"
    
    echo "    Adding listener: $LISTEN_ADDR:$LISTEN_PORT"
    $RPC nvmf_subsystem_add_listener "$SUBNQN" -t tcp \
        -f ipv4 -s $LISTEN_PORT -a "$LISTEN_ADDR" || echo "    ⚠ Listener exists"
    
    ((i++))
done

echo ""
echo "=========================================="
echo "✓ Target setup complete!"
echo "=========================================="
echo ""
echo "Subsystems created: $((i-1))"
echo "Listen address: $LISTEN_ADDR:$LISTEN_PORT"
echo "Block devices: NULL bdevs (no storage overhead)"
echo ""
echo "Configuration matches official SPDK performance test:"
echo "  • Socket implementation: posix (TCP)"
echo "  • iobuf pools: 32767 small, 16383 large"
echo "  • Zero-copy send: enabled"
echo "  • Max queue depth: 128"
echo "  • IO unit size: 128KB"
echo "  • Shared buffers: 8192"
echo ""
echo "Official test uses 14 devices, this setup uses $((i-1)) devices"
echo ""
echo "Next steps:"
echo "  1. Run performance test: sudo ./quick_tcp_test.sh"
echo "  2. Or customize: sudo QUEUE_DEPTH=256 ./run_tcp_perf_test_nvme.sh"
echo ""
