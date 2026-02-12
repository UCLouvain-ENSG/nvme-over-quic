#!/usr/bin/env bash
# Simple TCP+TLS test based on SPDK test/nvmf/target/tls.sh
# This version works with a single network interface

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPDK_DIR="$SCRIPT_DIR/.."
RPC="$SPDK_DIR/scripts/rpc.py"

# PSK configuration
PSK_FILE="/tmp/nvme_psk.key"
PSK_NAME="nvme_tcp_psk"
SUBNQN="nqn.2016-06.io.spdk:cnode1"
HOSTNQN="nqn.2016-06.io.spdk:host1"

# Generate PSK using format_interchange_psk format from test scripts
if [ ! -f "$PSK_FILE" ]; then
    echo "Generating PSK key..."
    # Generate 32 bytes (256 bits) hex key for SHA-256
    KEY_HEX=$(xxd -p -c32 -l 32 /dev/urandom)
    # Use Python to format with CRC32 checksum (same as SPDK test scripts)
    python3 - > "$PSK_FILE" <<EOF
import base64, zlib

key_hex = "$KEY_HEX"
key_bytes = bytes.fromhex(key_hex)
crc = zlib.crc32(key_bytes).to_bytes(4, byteorder="little")
b64 = base64.b64encode(key_bytes + crc).decode("utf-8")
# Format: NVMeTLSkey-1:<hash>:<base64(key+crc)>:
# hash: 01 = SHA-256 (requires 32-byte key)
print("NVMeTLSkey-1:01:{}:".format(b64), end="")
EOF
    chmod 600 "$PSK_FILE"
    echo "PSK saved to $PSK_FILE"
fi

echo "PSK content: $(cat $PSK_FILE)"
echo ""

# Ensure socket implementation is SSL (must be done before framework_start_init)
echo "Setting socket implementation to SSL..."
$RPC sock_set_default_impl -i ssl

echo "Starting framework initialization..."
$RPC framework_start_init

echo "Creating TCP transport..."
$RPC nvmf_create_transport -t TCP

echo "Creating subsystem..."
$RPC nvmf_create_subsystem "$SUBNQN" -s SPDK00000000000001 -m 10

echo "Adding listener with -k flag (enables TLS)..."
$RPC nvmf_subsystem_add_listener "$SUBNQN" -t TCP \
    -a 127.0.0.1 -s 4420 -k

echo "Creating malloc bdev..."
$RPC bdev_malloc_create 32 4096 -b malloc0

echo "Adding namespace..."
$RPC nvmf_subsystem_add_ns "$SUBNQN" malloc0 -n 1

echo "Adding PSK to keyring..."
$RPC keyring_file_add_key "$PSK_NAME" "$PSK_FILE"

echo "Adding host with PSK..."
$RPC nvmf_subsystem_add_host "$SUBNQN" "$HOSTNQN" --psk "$PSK_NAME"

echo ""
echo "=========================================="
echo "TCP+TLS target setup complete!"
echo "=========================================="
echo ""
echo "To test with spdk_nvme_perf:"
echo "  cd $SPDK_DIR/build/bin"
echo "  sudo ./spdk_nvme_perf -S ssl -q 64 -o 4096 -w randread -t 3 \\"
echo "    --psk-path $PSK_FILE \\"
echo "    -r 'trtype:TCP adrfam:IPv4 traddr:127.0.0.1 trsvcid:4420 subnqn:$SUBNQN hostnqn:$HOSTNQN'"
echo ""
