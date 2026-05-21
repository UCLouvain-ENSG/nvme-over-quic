#!/usr/bin/env bash
# Configure SPDK vhost to connect to an NVMf target and expose the bdev via a
# vhost-user socket that QEMU can attach to as a virtio-blk device.
#
# Run this AFTER vhost_run.sh is listening, and AFTER the NVMf target is up
# (controller_run.sh + nvmf_setup.sh).
#
# Usage: ./vhost_nvmf_setup.sh -t <tcp|tls|quic> [-i <ip>] [--rpc-sock <path>]
#                               [--socket-dir <dir>] [--ctrlr <name>]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SPDK_DIR="$SCRIPT_DIR/.."
RPC_BIN="$SPDK_DIR/scripts/rpc.py"

TRANSPORT="tcp"
TARGET_IP="127.0.0.1"
TARGET_PORT="4420"
SUBNQN="nqn.2026-04.io.spdk:cnode1"
HOSTNQN="nqn.2026-04.io.spdk:host1"
VHOST_CTRLR="vhost.blk.0"
RPC_SOCK="/var/tmp/vhost.sock"
SOCKET_DIR="/tmp/spdk_vhost"
PSK_FILE="$SCRIPT_DIR/nvme_psk.key"
PSK_NAME="nvme_psk"
BDEV_NAME="NvmeRemote"

usage() {
    cat <<EOF
Usage: $0 -t <tcp|tls|quic> [options]

  -t tcp|tls|quic       Transport mode (required)
  -i <ip>               NVMf target IP (default: 127.0.0.1)
  -s <port>             NVMf target port (default: 4420)
  --rpc-sock <path>     Vhost RPC socket (default: /var/tmp/vhost.sock)
  --socket-dir <dir>    Vhost socket directory (default: /tmp/spdk_vhost)
  --ctrlr <name>        Vhost controller name (default: vhost.blk.0)
  --subnqn <nqn>        Target subsystem NQN
  --hostnqn <nqn>       Host NQN
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -t) TRANSPORT="$2"; shift 2 ;;
        -i) TARGET_IP="$2"; shift 2 ;;
        -s) TARGET_PORT="$2"; shift 2 ;;
        --rpc-sock) RPC_SOCK="$2"; shift 2 ;;
        --socket-dir) SOCKET_DIR="$2"; shift 2 ;;
        --ctrlr) VHOST_CTRLR="$2"; shift 2 ;;
        --subnqn) SUBNQN="$2"; shift 2 ;;
        --hostnqn) HOSTNQN="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [ -z "$TRANSPORT" ]; then
    echo "Error: -t is required"
    usage
fi

TRANSPORT_LOWER=$(echo "$TRANSPORT" | tr '[:upper:]' '[:lower:]')

if [[ "$TRANSPORT_LOWER" != "tcp" && "$TRANSPORT_LOWER" != "tls" && "$TRANSPORT_LOWER" != "quic" ]]; then
    echo "Error: transport must be tcp, tls, or quic"
    exit 1
fi

RPC="$RPC_BIN -s $RPC_SOCK"

echo "Configuring SPDK vhost for NVMf/$TRANSPORT_LOWER"
echo "  Target:       $TARGET_IP:$TARGET_PORT"
echo "  NVMf NQN:     $SUBNQN"
echo "  Vhost socket: $SOCKET_DIR/$VHOST_CTRLR"
echo ""

# PSK is needed for tls and quic
if [ "$TRANSPORT_LOWER" = "tls" ] || [ "$TRANSPORT_LOWER" = "quic" ]; then
    "$SCRIPT_DIR/gen_psk.sh"
    echo "Using PSK: $(cat "$PSK_FILE")"
    echo ""
fi

# Set socket implementation before framework init (matches nvmf_setup.sh ordering)
if [ "$TRANSPORT_LOWER" = "tls" ]; then
    echo "Setting socket implementation to SSL (TLS over TCP)..."
    $RPC sock_set_default_impl -i ssl
elif [ "$TRANSPORT_LOWER" = "quic" ]; then
    echo "Setting socket implementation to UDP (QUIC)..."
    $RPC sock_set_default_impl -i udp
else
    echo "Setting socket implementation to POSIX (plain TCP)..."
    $RPC sock_set_default_impl -i posix
fi

echo "Starting framework..."
$RPC framework_start_init

# Load PSK into keyring for TLS/QUIC
if [ "$TRANSPORT_LOWER" = "tls" ] || [ "$TRANSPORT_LOWER" = "quic" ]; then
    echo "Loading PSK into keyring..."
    $RPC keyring_file_add_key "$PSK_NAME" "$PSK_FILE"
fi

# Attach to NVMf target as initiator
echo "Attaching to NVMf target ($TARGET_IP:$TARGET_PORT, $TRANSPORT_LOWER)..."
if [ "$TRANSPORT_LOWER" = "quic" ]; then
    $RPC bdev_nvme_attach_controller \
        -b "$BDEV_NAME" \
        -t QUIC -f IPv4 \
        -a "$TARGET_IP" -s "$TARGET_PORT" \
        -n "$SUBNQN" -q "$HOSTNQN" \
        -k "$PSK_NAME"
elif [ "$TRANSPORT_LOWER" = "tls" ]; then
    $RPC bdev_nvme_attach_controller \
        -b "$BDEV_NAME" \
        -t TCP -f IPv4 \
        -a "$TARGET_IP" -s "$TARGET_PORT" \
        -n "$SUBNQN" -q "$HOSTNQN" \
        -k "$PSK_NAME"
else
    $RPC bdev_nvme_attach_controller \
        -b "$BDEV_NAME" \
        -t TCP -f IPv4 \
        -a "$TARGET_IP" -s "$TARGET_PORT" \
        -n "$SUBNQN" -q "$HOSTNQN"
fi

# Discover the actual namespace bdev name (may be NvmeRemote0n1 or NvmeRemoten1
# depending on SPDK version/config)
NS_BDEV=$($RPC bdev_get_bdevs 2>/dev/null \
    | grep '"name"' | grep -i "${BDEV_NAME}" | head -1 \
    | sed 's/.*"name": "\(.*\)".*/\1/')
if [ -z "$NS_BDEV" ]; then
    NS_BDEV="${BDEV_NAME}0n1"
    echo "Warning: could not auto-detect bdev name, trying $NS_BDEV"
else
    echo "NVMf bdev: $NS_BDEV"
fi

# Create vhost-blk controller (exposes bdev as vhost-user socket)
echo "Creating vhost-blk controller '$VHOST_CTRLR' -> $NS_BDEV..."
$RPC vhost_create_blk_controller "$VHOST_CTRLR" "$NS_BDEV"

VHOST_SOCKET="$SOCKET_DIR/$VHOST_CTRLR"

echo ""
echo "=========================================="
echo "Vhost setup complete!"
echo "=========================================="
echo ""
echo "  Transport:    NVMf/$TRANSPORT_LOWER -> $TARGET_IP:$TARGET_PORT"
echo "  Vhost socket: $VHOST_SOCKET"
echo ""
echo "Start QEMU with:"
echo "  ./scripts/qemu_start.sh --image /path/to/vm.qcow2 --vhost-socket $VHOST_SOCKET"
echo ""
