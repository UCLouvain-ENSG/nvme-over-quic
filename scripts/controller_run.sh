#!/bin/bash

# Script to run SPDK NVMf target with gdb and logging
# Usage: ./controller_run.sh -l <logfile> [options]
# Options: -m <mask> (CPU mask for nvmf_tgt) for example -m 0x1 to run on CPU 0, -m 0x3 to run on CPU 0 and 1, etc.
#          -L <flag> (Log flag: all, nvmf, nvmf_quic, nvmf_tcp, sock, etc.)
LOGFILE=""
LOGFLAG=""
NVMF_OPTS="--wait-for-rpc"

while [[ $# -gt 0 ]]; do
    case $1 in
        -l)
            LOGFILE="$2"
            shift 2
            ;;
        -m)
            NVMF_OPTS="$NVMF_OPTS -m $2"
            shift 2
            ;;
        -L)
            LOGFLAG="$2"
            NVMF_OPTS="$NVMF_OPTS -L $2"
            shift 2
            ;;
        *)
            NVMF_OPTS="$NVMF_OPTS $1"
            shift
            ;;
    esac
done

# Enable eBPF for SO_REUSEPORT load balancing (if compiled with --with-ebpf)
export SPDK_UDP_EBPF_PATH="/etinfo/users2/soyong/Workspace/spdk/module/sock/udp/ebpf/reuseport_kern.o"

NVMF_TGT="../build/bin/nvmf_tgt"

if [ ! -f "$NVMF_TGT" ]; then
    echo "Error: nvmf_tgt not found at $NVMF_TGT"
    exit 1
fi

if [ -z "$LOGFILE" ]; then
    echo "Starting NVMf target (options: $NVMF_OPTS)..."
    [ -n "$LOGFLAG" ] && echo "  Log flag enabled: $LOGFLAG"
    [ -n "$SPDK_UDP_EBPF_PATH" ] && echo "  eBPF enabled: $SPDK_UDP_EBPF_PATH"
    cd ../build/bin
    sudo -E gdb --batch -ex 'set pagination off' -ex "run $NVMF_OPTS" -ex 'bt 20' ./nvmf_tgt 2>&1
else
    echo "Starting NVMf target with logging to $LOGFILE (options: $NVMF_OPTS)..."
    [ -n "$LOGFLAG" ] && echo "  Log flag enabled: $LOGFLAG"
    [ -n "$SPDK_UDP_EBPF_PATH" ] && echo "  eBPF enabled: $SPDK_UDP_EBPF_PATH"
    cd ../build/bin
    sudo -E gdb --batch -ex 'set pagination off' -ex "run $NVMF_OPTS" -ex 'bt 20' ./nvmf_tgt 2>&1 | tee "$LOGFILE"
fi
