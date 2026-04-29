#!/bin/bash

# Run spdk_nvme_perf (no profiling).
#
# Usage: ./host_run_bench.sh -m <tcp|tls|quic> -i <ip> [spdk_nvme_perf args...]
#
#   -m <mode>       tcp | tls | quic (default: tcp)
#   -i <ip>         target IP address (default: 127.0.0.1)
#   --save <file>   optionally save output to a log file
#   all other args are passed directly to spdk_nvme_perf
#
# Example:
#   ./host_run_bench.sh -m quic -i 192.168.1.10 -c 0x1 -q 1 -o 4096 -w randread -t 30

LOGFILE=""
MODE="tcp"
TARGET_IP="127.0.0.1"
SPDK_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --save) LOGFILE="$2"; shift 2 ;;
        -m)    MODE="$2";      shift 2 ;;
        -i)    TARGET_IP="$2"; shift 2 ;;
        *) SPDK_ARGS+=("$1"); shift ;;
    esac
done


PSK_PATH="$(cd "$(dirname "$0")" && pwd)/nvme_psk.key"
MODE_LOWER=$(echo "$MODE" | tr '[:upper:]' '[:lower:]')

case "$MODE_LOWER" in
    quic)
        TRANSPORT_ARGS=(--psk-path "$PSK_PATH"
            -r "trtype:QUIC adrfam:IPv4 traddr:$TARGET_IP trsvcid:4420 subnqn:nqn.2026-04.io.spdk:cnode1 hostnqn:nqn.2026-04.io.spdk:host1") ;;
    tls)
        TRANSPORT_ARGS=(-S ssl --psk-path "$PSK_PATH"
            -r "trtype:TCP adrfam:IPv4 traddr:$TARGET_IP trsvcid:4420 subnqn:nqn.2026-04.io.spdk:cnode1 hostnqn:nqn.2026-04.io.spdk:host1") ;;
    tcp)
        TRANSPORT_ARGS=(-S posix
            -r "trtype:TCP adrfam:IPv4 traddr:$TARGET_IP trsvcid:4420 subnqn:nqn.2026-04.io.spdk:cnode1 hostnqn:nqn.2026-04.io.spdk:host1") ;;
    *)
        echo "Error: unknown mode '$MODE'. Use tcp, tls, or quic."
        exit 1 ;;
esac

_BUILD_DIR="${SPDK_BUILD:-$(cd "$(dirname "$0")/../build" && pwd)}"
PERF_BIN="$_BUILD_DIR/bin/spdk_nvme_perf"

if [ ! -f "$PERF_BIN" ]; then
    echo "Error: spdk_nvme_perf not found at $PERF_BIN"
    exit 1
fi

if [ -n "$LOGFILE" ]; then
    # Properly quote arguments when using script
    # Use -f for flush mode to see real-time updates with \r
    cmd_args=()
    for arg in "${SPDK_ARGS[@]}" "${TRANSPORT_ARGS[@]}"; do
        cmd_args+=("$(printf '%q' "$arg")")
    done
    sudo script -f -q -c "$PERF_BIN ${cmd_args[*]}" /dev/null | tee "$LOGFILE"
else
    sudo "$PERF_BIN" "${SPDK_ARGS[@]}" "${TRANSPORT_ARGS[@]}"
fi
