#!/bin/bash
# Start SPDK vhost application as an NVMf-initiator-backed virtio-blk provider for QEMU.
#
# This is the bridge process between an NVMf target (TCP/TLS/QUIC) and QEMU guests:
#   nvmf_tgt  ──(NVMf/TCP|TLS|QUIC)──>  vhost  ──(vhost-user)──>  QEMU
#
# Usage: ./vhost_run.sh [-m <cpumask>] [--socket-dir <dir>] [--rpc-sock <path>] [--no-gdb]
#
# After starting, configure with vhost_nvmf_setup.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SOCKET_DIR="/tmp/spdk_vhost"
RPC_SOCK="/var/tmp/vhost.sock"
USE_GDB=false
VHOST_OPTS="--wait-for-rpc --no-pci"

while [[ $# -gt 0 ]]; do
    case $1 in
        -m)
            VHOST_OPTS="$VHOST_OPTS -m $2"
            shift 2
            ;;
        --socket-dir)
            SOCKET_DIR="$2"
            shift 2
            ;;
        --rpc-sock)
            RPC_SOCK="$2"
            shift 2
            ;;
        --gdb)
            USE_GDB=true
            shift
            ;;
        --no-gdb)
            USE_GDB=false
            shift
            ;;
        -L)
            VHOST_OPTS="$VHOST_OPTS -L $2"
            shift 2
            ;;
        *)
            VHOST_OPTS="$VHOST_OPTS $1"
            shift
            ;;
    esac
done

VHOST_BIN="$SCRIPT_DIR/../build/bin/vhost"

if [ ! -f "$VHOST_BIN" ]; then
    echo "Error: vhost binary not found at $VHOST_BIN"
    exit 1
fi

mkdir -p "$SOCKET_DIR"

VHOST_OPTS="$VHOST_OPTS -r $RPC_SOCK -S $SOCKET_DIR"

echo "Starting SPDK vhost (RPC socket: $RPC_SOCK, vhost dir: $SOCKET_DIR)"
echo "Options: $VHOST_OPTS"
echo ""
echo "After this starts, in another terminal run:"
echo "  sudo ./scripts/vhost_nvmf_setup.sh -t <tcp|tls|quic> --rpc-sock $RPC_SOCK"
echo ""

cd "$SCRIPT_DIR/../build/bin"
if $USE_GDB; then
    sudo -E gdb --batch -ex 'set pagination off' -ex "run $VHOST_OPTS" -ex 'bt 20' ./vhost 2>&1
else
    sudo -E ./vhost $VHOST_OPTS 2>&1
fi
