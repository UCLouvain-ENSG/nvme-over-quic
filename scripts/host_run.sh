#!/bin/bash

# Script to run SPDK NVMe perf client with gdb and logging
# Usage: ./host_run.sh -m <mode> -q <queue_depth> -o <block_size> -w <workload> [-t <time> | -d <num_ios>] --save <logfile>
# -t and -d are mutually exclusive. -d stops after exactly N IOs (sets -t to a large safety timeout).

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# Convert a DPDK corelist (e.g. "1,3,5-7") to a hex coremask (e.g. "0xea")
corelist_to_mask() {
    local list="$1" mask=0
    IFS=',' read -ra parts <<< "$list"
    for part in "${parts[@]}"; do
        part="${part// /}"
        if [[ "$part" == *-* ]]; then
            local a="${part%-*}" b="${part#*-}"
            for ((i=a; i<=b; i++)); do (( mask |= 1 << i )); done
        else
            (( mask |= 1 << part ))
        fi
    done
    printf '0x%x\n' "$mask"
}

# Default values
MODE="tcp"
QUEUE_DEPTH=2
BLOCK_SIZE=4096
WORKLOAD="randread"
TIME=1
LOGFILE=""
LOG_LEVEL=""  # Optional -T parameter (e.g., "nvme")
CORE_MASK="0x1"  # Default to core 0


# Add -M option for read percentage
READ_PERCENT=""

# Number of IOs to run (empty = unlimited, controlled by -t time instead)
# Set via -d; mutually exclusive with -t
NUM_IOS=""
USE_NUM_IOS=false
TARGET_IP="127.0.0.1"
LCORE_VAL=""
WARMUP_TIME=""

# Pre-process --save and --lcore long options
_ARGS=()
while [[ $# -gt 0 ]]; do
    if [ "$1" = "--save" ]; then
        LOGFILE="$2"; shift 2
    elif [ "$1" = "--lcore" ] || [ "$1" = "--lcores" ]; then
        LCORE_VAL="$2"; shift 2
    else
        _ARGS+=("$1"); shift
    fi
done
set -- "${_ARGS[@]}"

# Parse command line arguments
while getopts "m:q:o:w:t:T:c:M:d:i:a:" opt; do
    case $opt in
        m) MODE="$OPTARG" ;;
        q) QUEUE_DEPTH="$OPTARG" ;;
        o) BLOCK_SIZE="$OPTARG" ;;
        w) WORKLOAD="$OPTARG" ;;
        t) TIME="$OPTARG" ;;
        T) LOG_LEVEL="$OPTARG" ;;
        c) CORE_MASK="$OPTARG" ;;
        M) READ_PERCENT="$OPTARG" ;;
        d) NUM_IOS="$OPTARG"; USE_NUM_IOS=true ;;
        i) TARGET_IP="$OPTARG" ;;
        a) WARMUP_TIME="$OPTARG" ;;
        *)
            echo "Usage: $0 -m <tcp|tls|quic> -q <queue_depth> -o <block_size> -w <workload> [-t <time> | -d <num_ios>] --save <logfile> [-T <log_level>] [-c <core_mask>] [-M <read_percent>] [-i <ip>]"
            echo "Example: $0 -m tcp -q 2 -o 4096 -w randrw -t 1 --save client.log -T nvme -c 0x2 -M 70 -i 10.100.0.2"
            exit 1
            ;;
    esac
done

if [ -z "$LOGFILE" ]; then
    echo "Error: Log file must be specified with --save option"
    echo "Usage: $0 -m <tcp|tls|quic> -q <queue_depth> -o <block_size> -w <workload> -t <time> --save <logfile> [-T <log_level>] [-c <core_mask>]"
    exit 1
fi

# Enforce mutual exclusivity of -t and -d
if $USE_NUM_IOS && [ "$TIME" != "1" ]; then
    echo "Error: -t and -d are mutually exclusive"
    exit 1
fi

# If -d was used, override TIME with a large safety timeout so it doesn't expire first
if $USE_NUM_IOS; then
    TIME=999999
fi

NUM_IOS_OPT=""
[ -n "$NUM_IOS" ] && NUM_IOS_OPT="-d $NUM_IOS"

WARMUP_OPT=""
[ -n "$WARMUP_TIME" ] && WARMUP_OPT="-a $WARMUP_TIME"

# Build log level option if specified
LOG_LEVEL_OPT=""
if [ -n "$LOG_LEVEL" ]; then
    LOG_LEVEL_OPT="-T $LOG_LEVEL"
fi

# Build read percent option if specified
READ_PERCENT_OPT=""
if [ -n "$READ_PERCENT" ]; then
    READ_PERCENT_OPT="-M $READ_PERCENT"
fi

PERF_BIN="../build/bin/spdk_nvme_perf"

if [ ! -f "$PERF_BIN" ]; then
    echo "Error: spdk_nvme_perf not found at $PERF_BIN"
    exit 1
fi

# Make LOGFILE absolute before cd so tee writes to the caller's directory
[[ "$LOGFILE" != /* ]] && LOGFILE="$PWD/$LOGFILE"

# Build core option: --lcore corelist takes priority over -c mask
if [ -n "$LCORE_VAL" ]; then
    CORE_OPT="-c $(corelist_to_mask "$LCORE_VAL")"
else
    CORE_OPT="-c $CORE_MASK"
fi

cd ../build/bin

MODE_LOWER=$(echo "$MODE" | tr '[:upper:]' '[:lower:]')

if [ "$MODE_LOWER" = "quic" ]; then
    echo "Running NVMe perf client in QUIC mode..."
    echo "  Queue Depth: $QUEUE_DEPTH"
    echo "  Block Size: $BLOCK_SIZE"
    echo "  Workload: $WORKLOAD"
    echo "  Time: $TIME seconds"
    echo "  Log: $LOGFILE"
    echo "  Log Level: ${LOG_LEVEL:-none}"
    echo "  Core Mask: $CORE_MASK"
    

    sudo gdb --batch -ex 'set pagination off' \
        -ex "set environment QUIC_PAD_LAST_DATAGRAM $QUIC_PAD_LAST_DATAGRAM" \
        -ex "run $CORE_OPT -q $QUEUE_DEPTH -o $BLOCK_SIZE -w $WORKLOAD $READ_PERCENT_OPT -t $TIME $NUM_IOS_OPT $WARMUP_OPT $LOG_LEVEL_OPT --psk-path $SCRIPT_DIR/nvme_psk.key -r \"trtype:QUIC adrfam:IPv4 traddr:$TARGET_IP trsvcid:4420 subnqn:nqn.2026-04.io.spdk:cnode1 hostnqn:nqn.2026-04.io.spdk:host1\"" \
        -ex 'bt 15' -ex 'quit' ./spdk_nvme_perf 2>&1 | tee "$LOGFILE"

elif [ "$MODE_LOWER" = "tls" ]; then
    echo "Running NVMe perf client in TLS mode..."
    echo "  Queue Depth: $QUEUE_DEPTH"
    echo "  Block Size: $BLOCK_SIZE"
    echo "  Workload: $WORKLOAD"
    echo "  Time: $TIME seconds"
    echo "  Log: $LOGFILE"
    echo "  Log Level: ${LOG_LEVEL:-none}"
    echo "  Core Mask: $CORE_MASK"
    

    sudo gdb --batch -ex 'set pagination off' \
        -ex "run $CORE_OPT -S ssl -q $QUEUE_DEPTH -o $BLOCK_SIZE -w $WORKLOAD $READ_PERCENT_OPT -t $TIME $NUM_IOS_OPT $WARMUP_OPT $LOG_LEVEL_OPT --psk-path $SCRIPT_DIR/nvme_psk.key -r \"trtype:TCP adrfam:IPv4 traddr:$TARGET_IP trsvcid:4420 subnqn:nqn.2026-04.io.spdk:cnode1 hostnqn:nqn.2026-04.io.spdk:host1\"" \
        -ex 'bt 15' -ex 'quit' ./spdk_nvme_perf 2>&1 | tee "$LOGFILE"

elif [ "$MODE_LOWER" = "tcp" ]; then
    echo "Running NVMe perf client in TCP mode (no TLS)..."
    echo "  Queue Depth: $QUEUE_DEPTH"
    echo "  Block Size: $BLOCK_SIZE"
    echo "  Workload: $WORKLOAD"
    echo "  Time: $TIME seconds"
    echo "  Log: $LOGFILE"
    echo "  Log Level: ${LOG_LEVEL:-none}"
    echo "  Core Mask: $CORE_MASK"
    

    sudo gdb --batch -ex 'set pagination off' \
        -ex "run $CORE_OPT -S posix -q $QUEUE_DEPTH -o $BLOCK_SIZE -w $WORKLOAD $READ_PERCENT_OPT -t $TIME $NUM_IOS_OPT $WARMUP_OPT $LOG_LEVEL_OPT -r \"trtype:TCP adrfam:IPv4 traddr:$TARGET_IP trsvcid:4420 subnqn:nqn.2026-04.io.spdk:cnode1 hostnqn:nqn.2026-04.io.spdk:host1\"" \
        -ex 'bt 15' -ex 'quit' ./spdk_nvme_perf 2>&1 | tee "$LOGFILE"

else
    echo "Error: Invalid mode '$MODE'. Must be 'tcp', 'tls', or 'quic'"
    exit 1
fi
