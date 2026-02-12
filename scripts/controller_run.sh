#!/bin/bash

# Script to run SPDK NVMf target with gdb and logging
# Usage: ./controller_run.sh <logfile> [-c core_mask]

LOGFILE=""
CORE_MASK="0x1"  # Default to core 0

while [[ $# -gt 0 ]]; do
    case $1 in
        -c)
            CORE_MASK="$2"
            shift 2
            ;;
        *)
            LOGFILE="$1"
            shift
            ;;
    esac
done

if [ -z "$LOGFILE" ]; then
    echo "Usage: $0 <logfile> [-c core_mask]"
    echo "Example: $0 server_quic.log -c 0x2  # Run on core 1"
    echo "         $0 server_quic.log           # Run on core 0 (default)"
    exit 1
fi
NVMF_TGT="../build/bin/nvmf_tgt"

if [ ! -f "$NVMF_TGT" ]; then
    echo "Error: nvmf_tgt not found at $NVMF_TGT"
    exit 1
fi

echo "Starting NVMf target with logging to $LOGFILE (core mask: $CORE_MASK)..."
cd ../build/bin
# sudo gdb --batch -ex 'set pagination off' -ex 'run --wait-for-rpc -L nvmf_quic' -ex 'bt 20' ./nvmf_tgt 2>&1 | tee "$LOGFILE"
sudo gdb --batch -ex 'set pagination off' -ex "run -m $CORE_MASK --wait-for-rpc" -ex 'bt 20' ./nvmf_tgt 2>&1 | tee "$LOGFILE"
