#!/bin/bash

# Script to run SPDK NVMe perf client with gdb and logging
# Usage: ./host_run.sh -m <mode> -q <queue_depth> -o <block_size> -w <workload> -t <time> -l <logfile>

# Default values
MODE="quic"
QUEUE_DEPTH=2
BLOCK_SIZE=4096
WORKLOAD="randread"
TIME=1
LOGFILE=""
LOG_LEVEL=""  # Optional -T parameter (e.g., "nvme")
CORE_MASK="0x1"  # Default to core 0

# Parse command line arguments
while getopts "m:q:o:w:t:l:T:c:" opt; do
    case $opt in
        m) MODE="$OPTARG" ;;
        q) QUEUE_DEPTH="$OPTARG" ;;
        o) BLOCK_SIZE="$OPTARG" ;;
        w) WORKLOAD="$OPTARG" ;;
        t) TIME="$OPTARG" ;;
        l) LOGFILE="$OPTARG" ;;
        T) LOG_LEVEL="$OPTARG" ;;
        c) CORE_MASK="$OPTARG" ;;
        *)
            echo "Usage: $0 -m <quic|tcp> -q <queue_depth> -o <block_size> -w <workload> -t <time> -l <logfile> [-T <log_level>] [-c <core_mask>]"
            echo "Example: $0 -m quic -q 2 -o 4096 -w randread -t 1 -l client.log -T nvme -c 0x2"
            exit 1
            ;;
    esac
done

if [ -z "$LOGFILE" ]; then
    echo "Error: Log file must be specified with -l option"
    echo "Usage: $0 -m <quic|tcp> -q <queue_depth> -o <block_size> -w <workload> -t <time> -l <logfile> [-T <log_level>] [-c <core_mask>]"
    exit 1
fi

# Build log level option if specified
LOG_LEVEL_OPT=""
if [ -n "$LOG_LEVEL" ]; then
    LOG_LEVEL_OPT="-T $LOG_LEVEL"
fi

PERF_BIN="../build/bin/spdk_nvme_perf"

if [ ! -f "$PERF_BIN" ]; then
    echo "Error: spdk_nvme_perf not found at $PERF_BIN"
    exit 1
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
        -ex "run -c $CORE_MASK -q $QUEUE_DEPTH -o $BLOCK_SIZE -w $WORKLOAD -t $TIME $LOG_LEVEL_OPT --psk-path /tmp/nvme_quic_psk.key -r \"trtype:QUIC adrfam:IPv4 traddr:127.0.0.1 trsvcid:4420 subnqn:nqn.2016-06.io.spdk:cnode1 hostnqn:nqn.2016-06.io.spdk:host1\"" \
        -ex 'bt 15' -ex 'quit' ./spdk_nvme_perf 2>&1 | tee "$LOGFILE"

elif [ "$MODE_LOWER" = "tcp" ]; then
    echo "Running NVMe perf client in TCP mode..."
    echo "  Queue Depth: $QUEUE_DEPTH"
    echo "  Block Size: $BLOCK_SIZE"
    echo "  Workload: $WORKLOAD"
    echo "  Time: $TIME seconds"
    echo "  Log: $LOGFILE"
    echo "  Log Level: ${LOG_LEVEL:-none}"
    echo "  Core Mask: $CORE_MASK"
    
    sudo gdb --batch -ex 'set pagination off' \
        -ex "run -c $CORE_MASK -S ssl -q $QUEUE_DEPTH -o $BLOCK_SIZE -w $WORKLOAD -t $TIME $LOG_LEVEL_OPT --psk-path /tmp/nvme_psk.key -r \"trtype:TCP adrfam:IPv4 traddr:127.0.0.1 trsvcid:4420 subnqn:nqn.2016-06.io.spdk:cnode1 hostnqn:nqn.2016-06.io.spdk:host1\"" \
        -ex 'bt 15' -ex 'quit' ./spdk_nvme_perf 2>&1 | tee "$LOGFILE"

else
    echo "Error: Invalid mode '$MODE'. Must be 'quic' or 'tcp'"
    exit 1
fi
