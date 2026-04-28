#!/bin/bash

# Setup Soft-RoCE (Software RDMA) for local testing
# This allows RDMA over regular network interfaces without physical RDMA hardware

set -e

echo "Setting up Soft-RoCE for RDMA testing..."

# Load rdma_rxe module
if ! lsmod | grep -q rdma_rxe; then
    echo "Loading rdma_rxe kernel module..."
    sudo modprobe rdma_rxe
fi

# Check if rxe0 already exists
if rdma link show rxe0 2>/dev/null | grep -q rxe0; then
    echo "rxe0 already exists, removing it first..."
    sudo rdma link delete rxe0 || true
fi

# Add soft-roce device on ens0 (working interface)
echo "Adding Soft-RoCE device on ens0 interface..."
sudo rdma link add rxe0 type rxe netdev ens0

# Wait a moment for device to be ready
sleep 1

# Show RDMA devices
echo ""
echo "RDMA devices available:"
rdma link show
echo ""
ibv_devices
echo ""

# Get the IP to use
RDMA_IP="10.0.0.3"

echo "=========================================="
echo "Soft-RoCE setup complete!"
echo "=========================================="
echo ""
echo "RDMA device 'rxe0' is now available over ens0"
echo "Use address: $RDMA_IP in RDMA scripts"
echo ""
echo "To remove Soft-RoCE device:"
echo "  sudo rdma link delete rxe0"
echo ""
