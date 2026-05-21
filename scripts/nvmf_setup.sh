#!/usr/bin/env bash
# Unified NVMf target setup script
# Usage: ./nvmf_setup.sh -t <tcp|tls|quic> -b <m|n|r> [-n <count>] [--ns <count>]

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPDK_DIR="$SCRIPT_DIR/.."
RPC="$SPDK_DIR/scripts/rpc.py"

# Default configuration
TRANSPORT=""
BDEV_TYPE=""
NS_COUNT=1
ADDRESS="10.100.10.18"
NVME_PCIE="0000:02:00.0"
MAX_QUEUE_DEPTH=256
SUBNQN="nqn.2026-04.io.spdk:cnode1"
HOSTNQN="nqn.2026-04.io.spdk:host1"
PSK_FILE="$SCRIPT_DIR/nvme_psk.key"
PSK_NAME="nvme_psk"
ENABLE_KTLS=false

# Pre-process long options (getopts doesn't support long options)
_ARGS=()
while [[ $# -gt 0 ]]; do
    if [ "$1" = "--ns" ]; then
        NS_COUNT="$2"; shift 2
    elif [ "$1" = "--enable-ktls" ]; then
        ENABLE_KTLS=true; shift
    else
        _ARGS+=("$1"); shift
    fi
done
set -- "${_ARGS[@]}"

# Parse arguments
while getopts "t:b:n:a:Q:p:" opt; do
    case $opt in
        t) TRANSPORT="$OPTARG" ;;
        b) BDEV_TYPE="$OPTARG" ;;
        n) NS_COUNT="$OPTARG" ;;
        a) ADDRESS="$OPTARG" ;;
        Q) MAX_QUEUE_DEPTH="$OPTARG" ;;
        p) NVME_PCIE="$OPTARG" ;;
        *) 
            echo "Usage: $0 -t <tcp|tls|quic> -b <m|n|r> [-n|--ns <count>] [-a <address>] [-Q <max_queue_depth>] [-p <pcie_addr>] [--enable-ktls]"
            echo "  -t: Transport type (tcp=TCP, tls=TCP+TLS, quic=QUIC+TLS)"
            echo "  -b: Block device (m=malloc, n=null, r=real NVMe passthrough)"
            echo "  -n/--ns: Number of namespaces (all bdev types; split for -b r, multiple mallocs for -b m)"
            echo "  -a: Listen address (default: 127.0.0.1)"
            echo "  -Q: Max IO queue depth (default: 128)"
            echo "  -p: PCIe address for real NVMe (-b r, default: 0000:02:00.0)"
            echo "  --enable-ktls: Enable kernel TLS offload (only for -t tls)"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$TRANSPORT" ] || [ -z "$BDEV_TYPE" ]; then
    echo "Error: -t and -b are required"
    echo "Usage: $0 -t <tcp|tls|quic> -b <m|n> [-n <count>] [-a <address>] [--enable-ktls]"
    exit 1
fi

# Validate transport
if [ "$TRANSPORT" != "tcp" ] && [ "$TRANSPORT" != "tls" ] && [ "$TRANSPORT" != "quic" ]; then
    echo "Error: -t must be tcp, tls, or quic"
    exit 1
fi

# Validate bdev type
if [ "$BDEV_TYPE" != "m" ] && [ "$BDEV_TYPE" != "n" ] && [ "$BDEV_TYPE" != "r" ]; then
    echo "Error: -b must be m (malloc), n (null), or r (real NVMe)"
    exit 1
fi


echo "Configuration:"
echo "  Transport: $TRANSPORT"
if [ "$TRANSPORT" = "tls" ] && [ "$ENABLE_KTLS" = true ]; then
    echo "  kTLS: enabled"
fi
echo "  Block device: $BDEV_TYPE"
if [ "$BDEV_TYPE" = "r" ]; then
    echo "  NVMe PCIe: $NVME_PCIE"
fi
echo "  Namespace count: $NS_COUNT"
echo "  Max queue depth: $MAX_QUEUE_DEPTH"
echo ""

# Generate PSK if needed (for tls or quic)
if [ "$TRANSPORT" = "tls" ] || [ "$TRANSPORT" = "quic" ]; then
    "$SCRIPT_DIR/gen_psk.sh"
    echo "PSK: $(cat $PSK_FILE)"
    echo ""
fi

# Set socket implementation based on transport
if [ "$TRANSPORT" = "tls" ]; then
    echo "Setting socket implementation to SSL..."
    $RPC sock_set_default_impl -i ssl
    if [ "$ENABLE_KTLS" = true ]; then
        echo "Enabling kTLS for SSL socket implementation..."
        $RPC sock_impl_set_options -i ssl --ktls
    fi
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
    echo "Creating QUIC transport (max_queue_depth=$MAX_QUEUE_DEPTH)..."
    $RPC nvmf_create_transport -t QUIC --max-queue-depth $MAX_QUEUE_DEPTH
else
    echo "Creating TCP transport..."
    $RPC nvmf_create_transport -t TCP
fi

echo "Creating subsystem..."
$RPC nvmf_create_subsystem "$SUBNQN" -s SPDK00000000000001 -m 10

# Add listener
if [ "$TRANSPORT" = "quic" ]; then
    echo "Adding QUIC listener on $ADDRESS:4420..."
    $RPC nvmf_subsystem_add_listener "$SUBNQN" -t QUIC -a "$ADDRESS" -s 4420
elif [ "$TRANSPORT" = "tls" ]; then
    echo "Adding TCP listener with TLS on $ADDRESS:4420..."
    $RPC nvmf_subsystem_add_listener "$SUBNQN" -t TCP -a "$ADDRESS" -s 4420 -k
else
    echo "Adding TCP listener on $ADDRESS:4420..."
    $RPC nvmf_subsystem_add_listener "$SUBNQN" -t TCP -a "$ADDRESS" -s 4420
fi

# Create block devices and namespaces
if [ "$BDEV_TYPE" = "m" ]; then
    echo "Creating $NS_COUNT malloc bdev(s) and namespace(s)..."
    for i in $(seq 1 $NS_COUNT); do
        $RPC bdev_malloc_create 32 4096 -b "malloc$((i-1))"
        echo "Adding namespace $i (malloc$((i-1)))..."
        $RPC nvmf_subsystem_add_ns "$SUBNQN" "malloc$((i-1))" -n $i
    done
elif [ "$BDEV_TYPE" = "r" ]; then
    echo "Attaching real NVMe controller at $NVME_PCIE..."
    NVME_NS=$($RPC bdev_nvme_attach_controller -t PCIe -b nvme_passthru -a "$NVME_PCIE" | tr -d '[]",' | awk 'NF{print $1; exit}')
    if [ "$NS_COUNT" -gt 1 ]; then
        echo "Splitting $NVME_NS into $NS_COUNT namespaces..."
        $RPC bdev_split_create "$NVME_NS" "$NS_COUNT"
        for i in $(seq 1 $NS_COUNT); do
            echo "Adding namespace $i (${NVME_NS}p$((i-1)))..."
            $RPC nvmf_subsystem_add_ns "$SUBNQN" "${NVME_NS}p$((i-1))" -n $i
        done
    else
        echo "Adding namespace ($NVME_NS)..."
        $RPC nvmf_subsystem_add_ns "$SUBNQN" "$NVME_NS" -n 1
    fi
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
if [ "$TRANSPORT" = "tls" ] && [ "$ENABLE_KTLS" = true ]; then
    echo "  kTLS: enabled"
fi
if [ "$BDEV_TYPE" = "r" ]; then
    echo "  Block device: real NVMe ($NVME_PCIE → nvme_passthru0n1)"
else
    echo "  Block device: $BDEV_TYPE ($NS_COUNT namespace(s))"
fi
echo "  Subsystem NQN: $SUBNQN"
echo ""

# Generate test command
if [ "$TRANSPORT" = "quic" ]; then
    TRTYPE="QUIC"
    EXTRA_OPTS="--psk-path $PSK_FILE"
elif [ "$TRANSPORT" = "tls" ]; then
    TRTYPE="TCP"
    EXTRA_OPTS="-S ssl --psk-path $PSK_FILE"
    if [ "$ENABLE_KTLS" = true ]; then
        EXTRA_OPTS="$EXTRA_OPTS --enable-ktls"
    fi
else
    TRTYPE="TCP"
    EXTRA_OPTS=""
fi

echo "To test with spdk_nvme_perf:"
echo "  cd $SPDK_DIR/build/bin"
echo "  sudo ./spdk_nvme_perf -q 64 -o 4096 -w randread -t 3 $EXTRA_OPTS \\"
echo "    -r 'trtype:$TRTYPE adrfam:IPv4 traddr:$ADDRESS trsvcid:4420 subnqn:$SUBNQN hostnqn:$HOSTNQN'"
echo ""
