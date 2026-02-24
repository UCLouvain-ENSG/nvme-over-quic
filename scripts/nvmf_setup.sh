#!/usr/bin/env bash
# Unified NVMf target setup script
# Usage: ./nvmf_setup.sh -t <tcp|tls|quic> -b <m|n> [-n <count>]

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPDK_DIR="$SCRIPT_DIR/.."
RPC="$SPDK_DIR/scripts/rpc.py"

# Default configuration
TRANSPORT=""
BDEV_TYPE=""
NS_COUNT=1
SUBNQN="nqn.2016-06.io.spdk:cnode1"
HOSTNQN="nqn.2016-06.io.spdk:host1"
PSK_FILE="/tmp/nvme_psk.key"
PSK_NAME="nvme_psk"

# Parse arguments
while getopts "t:b:n:" opt; do
    case $opt in
        t) TRANSPORT="$OPTARG" ;;
        b) BDEV_TYPE="$OPTARG" ;;
        n) NS_COUNT="$OPTARG" ;;
        *) 
            echo "Usage: $0 -t <tcp|tls|quic> -b <m|n> [-n <count>]"
            echo "  -t: Transport type (tcp=TCP, tls=TCP+TLS, quic=QUIC+TLS)"
            echo "  -b: Block device (m=malloc, n=null)"
            echo "  -n: Number of namespaces (only for null device)"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$TRANSPORT" ] || [ -z "$BDEV_TYPE" ]; then
    echo "Error: -t and -b are required"
    echo "Usage: $0 -t <tcp|tls|quic> -b <m|n> [-n <count>]"
    exit 1
fi

# Validate transport
if [ "$TRANSPORT" != "tcp" ] && [ "$TRANSPORT" != "tls" ] && [ "$TRANSPORT" != "quic" ]; then
    echo "Error: -t must be tcp, tls, or quic"
    exit 1
fi

# Validate bdev type
if [ "$BDEV_TYPE" != "m" ] && [ "$BDEV_TYPE" != "n" ]; then
    echo "Error: -b must be m (malloc) or n (null)"
    exit 1
fi

# Validate namespace count
if [ "$BDEV_TYPE" = "m" ] && [ "$NS_COUNT" -gt 1 ]; then
    echo "Warning: -n option only applies to null device (-b n), ignoring -n $NS_COUNT"
    NS_COUNT=1
fi

echo "Configuration:"
echo "  Transport: $TRANSPORT"
echo "  Block device: $BDEV_TYPE"
echo "  Namespace count: $NS_COUNT"
echo ""

# Generate PSK if needed (for tls or quic)
if [ "$TRANSPORT" = "tls" ] || [ "$TRANSPORT" = "quic" ]; then
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
    echo "PSK: $(cat $PSK_FILE)"
    echo ""
fi

# Set socket implementation based on transport
if [ "$TRANSPORT" = "tls" ]; then
    echo "Setting socket implementation to SSL..."
    $RPC sock_set_default_impl -i ssl
elif [ "$TRANSPORT" = "quic" ]; then
    echo "Setting socket implementation to UDP..."
    $RPC sock_set_default_impl -i udp
else
    echo "Setting socket implementation to POSIX (TCP)..."
    $RPC sock_set_default_impl -i posix
fi

echo "Starting framework initialization..."
$RPC framework_start_init

# Create transport
if [ "$TRANSPORT" = "quic" ]; then
    echo "Creating QUIC transport..."
    $RPC nvmf_create_transport -t QUIC
else
    echo "Creating TCP transport..."
    $RPC nvmf_create_transport -t TCP
fi

echo "Creating subsystem..."
$RPC nvmf_create_subsystem "$SUBNQN" -s SPDK00000000000001 -m 10

# Add listener
if [ "$TRANSPORT" = "quic" ]; then
    echo "Adding QUIC listener on 127.0.0.1:4420..."
    $RPC nvmf_subsystem_add_listener "$SUBNQN" -t QUIC -a 127.0.0.1 -s 4420
elif [ "$TRANSPORT" = "tls" ]; then
    echo "Adding TCP listener with TLS on 127.0.0.1:4420..."
    $RPC nvmf_subsystem_add_listener "$SUBNQN" -t TCP -a 127.0.0.1 -s 4420 -k
else
    echo "Adding TCP listener on 127.0.0.1:4420..."
    $RPC nvmf_subsystem_add_listener "$SUBNQN" -t TCP -a 127.0.0.1 -s 4420
fi

# Create block devices and namespaces
if [ "$BDEV_TYPE" = "m" ]; then
    echo "Creating malloc bdev..."
    $RPC bdev_malloc_create 32 4096 -b malloc0
    echo "Adding namespace..."
    $RPC nvmf_subsystem_add_ns "$SUBNQN" malloc0 -n 1
else
    echo "Creating $NS_COUNT null bdev(s) and namespace(s)..."
    for i in $(seq 1 $NS_COUNT); do
        $RPC bdev_null_create null$i 100 4096
        $RPC nvmf_subsystem_add_ns "$SUBNQN" null$i -n $i
    done
fi

# Add PSK and host if needed
if [ "$TRANSPORT" = "tls" ] || [ "$TRANSPORT" = "quic" ]; then
    echo "Adding PSK to keyring..."
    $RPC keyring_file_add_key "$PSK_NAME" "$PSK_FILE"
    echo "Adding host with PSK..."
    $RPC nvmf_subsystem_add_host "$SUBNQN" "$HOSTNQN" --psk "$PSK_NAME"
else
    echo "Adding host (allow any)..."
    $RPC nvmf_subsystem_allow_any_host "$SUBNQN" --allow-any-host
fi

echo ""
echo "=========================================="
echo "NVMf target setup complete!"
echo "=========================================="
echo ""
echo "Configuration:"
echo "  Transport: $TRANSPORT"
echo "  Block device: $BDEV_TYPE ($NS_COUNT namespace(s))"
echo "  Subsystem NQN: $SUBNQN"
echo ""

# Generate test command
if [ "$TRANSPORT" = "quic" ]; then
    TRTYPE="QUIC"
    EXTRA_OPTS="--psk-path $PSK_FILE"
elif [ "$TRANSPORT" = "tls" ]; then
    TRTYPE="TCP"
    EXTRA_OPTS="-S ssl --psk-path $PSK_FILE"
else
    TRTYPE="TCP"
    EXTRA_OPTS=""
fi

echo "To test with spdk_nvme_perf:"
echo "  cd $SPDK_DIR/build/bin"
echo "  sudo ./spdk_nvme_perf -q 64 -o 4096 -w randread -t 3 $EXTRA_OPTS \\"
echo "    -r 'trtype:$TRTYPE adrfam:IPv4 traddr:127.0.0.1 trsvcid:4420 subnqn:$SUBNQN hostnqn:$HOSTNQN'"
echo ""
