#!/usr/bin/env bash
#
# SPDK QUIC NVMe-oF Target Setup Script
# This script configures an NVMe-oF target with QUIC transport

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RPC_PY="$SCRIPT_DIR/rpc.py"

# Configuration
TRANSPORT="QUIC"
BDEV_NAME="Malloc0"
BDEV_BLOCK_SIZE=512
BDEV_NUM_BLOCKS=512
SUBSYSTEM_NQN="nqn.2016-06.io.spdk:cnode1"
SUBSYSTEM_SERIAL="SPDK00000000000001"
LISTEN_ADDR="127.0.0.1"
LISTEN_PORT=4420

echo "==> Setting up SPDK NVMe-oF Target with QUIC transport"

# Create QUIC transport
echo "==> Creating QUIC transport..."
sudo "$RPC_PY" nvmf_create_transport -t $TRANSPORT
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create QUIC transport"
    exit 1
fi

# Create malloc bdev (RAM-based storage)
echo "==> Creating malloc bdev: $BDEV_NAME (${BDEV_NUM_BLOCKS} blocks x ${BDEV_BLOCK_SIZE} bytes = $((BDEV_BLOCK_SIZE * BDEV_NUM_BLOCKS)) bytes)"
sudo "$RPC_PY" bdev_malloc_create -b $BDEV_NAME $BDEV_BLOCK_SIZE $BDEV_NUM_BLOCKS
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create bdev"
    exit 1
fi

# Create NVMe-oF subsystem
echo "==> Creating NVMe-oF subsystem: $SUBSYSTEM_NQN"
sudo "$RPC_PY" nvmf_create_subsystem $SUBSYSTEM_NQN -a -s $SUBSYSTEM_SERIAL
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create subsystem"
    exit 1
fi

# Add namespace to subsystem
echo "==> Adding namespace $BDEV_NAME to subsystem $SUBSYSTEM_NQN"
sudo "$RPC_PY" nvmf_subsystem_add_ns $SUBSYSTEM_NQN $BDEV_NAME
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to add namespace"
    exit 1
fi

# Add QUIC listener
echo "==> Adding QUIC listener at $LISTEN_ADDR:$LISTEN_PORT"
sudo "$RPC_PY" nvmf_subsystem_add_listener $SUBSYSTEM_NQN -t $TRANSPORT -a $LISTEN_ADDR -s $LISTEN_PORT
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to add listener"
    exit 1
fi

echo ""
echo "==> SUCCESS! NVMe-oF target is ready"
echo ""
echo "Configuration:"
echo "  Transport:  $TRANSPORT"
echo "  Subsystem:  $SUBSYSTEM_NQN"
echo "  Namespace:  $BDEV_NAME ($(((BDEV_BLOCK_SIZE * BDEV_NUM_BLOCKS) / 1024)) KB)"
echo "  Listen:     $LISTEN_ADDR:$LISTEN_PORT"
echo ""
echo "To test with spdk_nvme_perf:"
echo "  sudo ./build/bin/spdk_nvme_perf -q 128 -o 4096 -w randread -t 10 \\"
echo "    -r 'trtype:QUIC adrfam:IPv4 traddr:$LISTEN_ADDR trsvcid:$LISTEN_PORT subnqn:$SUBSYSTEM_NQN'"
echo ""
