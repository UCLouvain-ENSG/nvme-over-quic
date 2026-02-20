#!/usr/bin/env bash
# RDMA setup for NVMe-oF target using NVMe partition
# Uses /dev/nvme0n1p5 as storage backend

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPDK_DIR="$SCRIPT_DIR/.."
RPC="$SPDK_DIR/scripts/rpc.py"

# NVMe partition configuration
NVME_PARTITION="/dev/nvme0n1p5"
BDEV_NAME="nvme_part5"

# Configuration
SUBNQN="nqn.2016-06.io.spdk:cnode1"
HOSTNQN="nqn.2016-06.io.spdk:host1"
RDMA_ADDR="10.0.0.3"  # ens0 with Soft-RoCE (requires ./setup_soft_roce.sh first)
RDMA_PORT="4420"

# Check if partition exists
if [ ! -b "$NVME_PARTITION" ]; then
    echo "Error: NVMe partition $NVME_PARTITION not found!"
    echo "Available block devices:"
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINT | grep -E "(nvme|NAME)"
    exit 1
fi

# Check if partition is mounted
if mountpoint -q "$NVME_PARTITION" 2>/dev/null || grep -qs "$NVME_PARTITION" /proc/mounts; then
    echo "Error: $NVME_PARTITION is currently mounted!"
    echo "Please unmount it first: sudo umount $NVME_PARTITION"
    exit 1
fi

echo "Using NVMe partition: $NVME_PARTITION"
lsblk "$NVME_PARTITION" -o NAME,SIZE,TYPE,FSTYPE

echo "Starting framework initialization..."
$RPC framework_start_init

echo "Creating RDMA transport..."
$RPC nvmf_create_transport -t RDMA

echo "Creating subsystem..."
$RPC nvmf_create_subsystem "$SUBNQN" -s SPDK00000000000001 -m 10

echo "Adding RDMA listener on $RDMA_ADDR:$RDMA_PORT..."
$RPC nvmf_subsystem_add_listener "$SUBNQN" -t RDMA \
    -a "$RDMA_ADDR" -s "$RDMA_PORT"

echo "Creating AIO bdev from NVMe partition..."
$RPC bdev_aio_create "$NVME_PARTITION" "$BDEV_NAME"

echo "Verifying bdev creation..."
$RPC bdev_get_bdevs -b "$BDEV_NAME"

echo "Adding namespace..."
$RPC nvmf_subsystem_add_ns "$SUBNQN" "$BDEV_NAME" -n 1

echo "Allowing any host..."
$RPC nvmf_subsystem_allow_any_host "$SUBNQN"

echo ""
echo "=========================================="
echo "RDMA target setup complete!"
echo "Using real NVMe partition: $NVME_PARTITION"
echo "=========================================="
echo ""
echo "To test with spdk_nvme_perf:"
echo "  cd $SPDK_DIR/build/bin"
echo "  sudo ./spdk_nvme_perf -q 64 -o 4096 -w randread -t 10 \\"
echo "    -r 'trtype:RDMA adrfam:IPv4 traddr:$RDMA_ADDR trsvcid:$RDMA_PORT subnqn:$SUBNQN'"
echo ""
echo "Or use the perf test script:"
echo "  ./perf_test_rdma.sh -q 64 -o 4096 -w randread -t 10"
echo ""
