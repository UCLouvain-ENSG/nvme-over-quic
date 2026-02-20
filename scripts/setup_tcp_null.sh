#!/usr/bin/env bash
# TCP+TLS setup with PSK authentication using NULL bdev
# NULL bdev for pure transport/CPU testing without storage overhead

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPDK_DIR="$SCRIPT_DIR/.."
RPC="$SPDK_DIR/scripts/rpc.py"

# PSK configuration
PSK_FILE="/tmp/nvme_psk.key"
PSK_NAME="nvme_tcp_psk"
SUBNQN="nqn.2016-06.io.spdk:cnode1"
HOSTNQN="nqn.2016-06.io.spdk:host1"

# Generate PSK
if [ ! -f "$PSK_FILE" ]; then
    echo "Generating PSK key..."
    KEY_HEX=$(xxd -p -c32 -l 32 /dev/urandom)
    python3 - > "$PSK_FILE" <<EOF
import base64, zlib

key_hex = "$KEY_HEX"
key_bytes = bytes.fromhex(key_hex)
crc = zlib.crc32(key_bytes).to_bytes(4, byteorder="little")
b64 = base64.b64encode(key_bytes + crc).decode("utf-8")
print("NVMeTLSkey-1:01:{}:".format(b64), end="")
EOF
    chmod 600 "$PSK_FILE"
    echo "PSK saved to $PSK_FILE"
fi

echo "PSK content: $(cat $PSK_FILE)"
echo ""

echo "Starting framework initialization..."
$RPC framework_start_init

echo "Creating TCP transport with TLS..."
$RPC nvmf_create_transport -t TCP -u 8192 -c 0

echo "Creating subsystem..."
$RPC nvmf_create_subsystem "$SUBNQN" -s SPDK00000000000001 -m 10

echo "Adding TCP listener on 127.0.0.1:4420..."
$RPC nvmf_subsystem_add_listener "$SUBNQN" -t TCP \
    -a 127.0.0.1 -s 4420 --secure-channel

echo "Creating NULL bdev (10GB virtual)..."
$RPC bdev_null_create null0 2621440 4096

echo "Verifying bdev creation..."
$RPC bdev_get_bdevs -b null0

echo "Adding namespace..."
$RPC nvmf_subsystem_add_ns "$SUBNQN" null0 -n 1

echo "Adding PSK to keyring..."
$RPC keyring_file_add_key "$PSK_NAME" "$PSK_FILE"

echo "Adding host with PSK..."
$RPC nvmf_subsystem_add_host "$SUBNQN" "$HOSTNQN" --psk "$PSK_NAME"

echo ""
echo "=========================================="
echo "TCP+TLS target setup complete!"
echo "Using NULL bdev (no storage overhead)"
echo "=========================================="
echo ""
echo "To test with spdk_nvme_perf:"
echo "  cd $SPDK_DIR/build/bin"
echo "  sudo ./spdk_nvme_perf -S ssl -q 64 -o 4096 -w randread -t 10 \\"
echo "    --psk-path $PSK_FILE \\"
echo "    -r 'trtype:TCP adrfam:IPv4 traddr:127.0.0.1 trsvcid:4420 subnqn:$SUBNQN hostnqn:$HOSTNQN'"
echo ""
echo "Or use the perf test script:"
echo "  ./perf_test_tcp.sh -q 64 -o 4096 -w randread -t 10"
echo ""
