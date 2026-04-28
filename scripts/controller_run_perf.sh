#!/bin/bash

# Script to run SPDK NVMf target with perf profiling
# Usage: ./controller_run_perf.sh -p <perf_output> [-m core_mask] [-l logfile] [perf options] [nvmf options]

LOGFILE=""
PERF_OUTPUT=""
PERF_OPTS=""
NVMF_OPTS="--wait-for-rpc"

while [[ $# -gt 0 ]]; do
    case $1 in
        -p)
            PERF_OUTPUT="$2"
            shift 2
            ;;
        -l)
            LOGFILE="$2"
            shift 2
            ;;
        -m)
            NVMF_OPTS="$NVMF_OPTS -m $2"
            shift 2
            ;;
        -D|-F|-f|-c|-e|-P|--call-graph|--freq)
            # Perf-specific options (with argument)
            PERF_OPTS="$PERF_OPTS $1 $2"
            shift 2
            ;;
        -a|-k|--all-cpus)
            # Perf-specific options (without argument)
            PERF_OPTS="$PERF_OPTS $1"
            shift
            ;;
        *)
            # Other options go to nvmf_tgt
            NVMF_OPTS="$NVMF_OPTS $1"
            shift
            ;;
    esac
done

if [ -z "$PERF_OUTPUT" ]; then
    echo "Error: perf output file required"
    echo "Usage: $0 -p <perf_output.data> [-m core_mask] [-l logfile] [other options]"
    echo "Example: $0 -p server_perf.data -m 0x1000"
    echo "         $0 -p server_perf.data -m 0x1000 -l server.log"
    exit 1
fi

NVMF_TGT="../build/bin/nvmf_tgt"

if [ ! -f "$NVMF_TGT" ]; then
    echo "Error: nvmf_tgt not found at $NVMF_TGT"
    exit 1
fi

cd ../build/bin

if [ -z "$LOGFILE" ]; then
    echo "Starting NVMf target with perf profiling..."
    echo "Perf output: $PERF_OUTPUT"
    echo "Perf options: $PERF_OPTS"
    echo "NVMf options: $NVMF_OPTS"
    echo ""
    sudo perf record -g -o "$PERF_OUTPUT" $PERF_OPTS ./nvmf_tgt $NVMF_OPTS
else
    echo "Starting NVMf target with perf profiling and logging..."
    echo "Perf output: $PERF_OUTPUT"
    echo "Perf options: $PERF_OPTS"
    echo "Log file: $LOGFILE"
    echo "NVMf options: $NVMF_OPTS"
    echo ""
    sudo perf record -g -o "$PERF_OUTPUT" $PERF_OPTS ./nvmf_tgt $NVMF_OPTS 2>&1 | tee "$LOGFILE"
fi

echo ""
echo "Perf data saved to: $PERF_OUTPUT"
echo ""
echo "To analyze the perf data:"
echo "  sudo perf report -i $PERF_OUTPUT"
echo "  sudo perf report -i $PERF_OUTPUT --no-children --no-inline"
echo "  sudo perf report -i $PERF_OUTPUT --stdio > analysis.txt"
