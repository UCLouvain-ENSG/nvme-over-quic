#!/usr/bin/env bash
# RDMA setup for NVMe-oF target
# Uses malloc bdev for storage

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPDK_DIR="$SCRIPT_DIR/.."
RPC="$SPDK_DIR/scripts/rpc.py"

# Configuration
SUBNQN="nqn.2016-06.io.spdk:cnode1"
HOSTNQN="nqn.2016-06.io.spdk:host1"
RDMA_ADDR="10.0.0.3"  # ens0 with Soft-RoCE (requires ./setup_soft_roce.sh first)
RDMA_PORT="4420"

echo "Starting framework initialization..."
$RPC framework_start_init

echo "Creating RDMA transport..."
$RPC nvmf_create_transport -t RDMA

echo "Creating subsystem..."
$RPC nvmf_create_subsystem "$SUBNQN" -s SPDK00000000000001 -m 10

echo "Adding RDMA listener on $RDMA_ADDR:$RDMA_PORT..."
$RPC nvmf_subsystem_add_listener "$SUBNQN" -t RDMA \
    -a "$RDMA_ADDR" -s "$RDMA_PORT"

echo "Creating malloc bdev..."
$RPC bdev_malloc_create 32 4096 -b malloc0

echo "Adding namespace..."
$RPC nvmf_subsystem_add_ns "$SUBNQN" malloc0 -n 1

echo "Allowing any host..."
$RPC nvmf_subsystem_allow_any_host "$SUBNQN"

echo ""
echo "=========================================="
echo "RDMA target setup complete!"
echo "=========================================="
echo ""
echo "To test with spdk_nvme_perf:"
echo "  cd $SPDK_DIR/build/bin"
echo "  sudo ./spdk_nvme_perf -q 64 -o 4096 -w randread -t 10 \\"
echo "    -r 'trtype:RDMA adrfam:IPv4 traddr:$RDMA_ADDR trsvcid:$RDMA_PORT subnqn:$SUBNQN'"
echo ""
echo "Note: Make sure RDMA NICs are configured and connected"
echo ""
