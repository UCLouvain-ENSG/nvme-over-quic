#!/bin/bash

# Script to run SPDK NVMe perf for QUIC
# Usage: ./perf_test_quic.sh [-q QUEUE_DEPTH] [-o BLOCK_SIZE] [-w WORKLOAD] [-t TEST_TIME]

# Default values
QUEUE_DEPTH=16
BLOCK_SIZE=4096
WORKLOAD="randread"
TEST_TIME=15

# Parse arguments
while getopts "q:o:w:t:" opt; do
  case $opt in
    q) QUEUE_DEPTH="$OPTARG" ;;
    o) BLOCK_SIZE="$OPTARG" ;;
    w) WORKLOAD="$OPTARG" ;;
    t) TEST_TIME="$OPTARG" ;;
    *) echo "Usage: $0 [-q QUEUE_DEPTH] [-o BLOCK_SIZE] [-w WORKLOAD] [-t TEST_TIME]"
       echo "  Defaults: -q 16 -o 4096 -w randread -t 15"
       exit 1 ;;
  esac
done

cd ../build/bin

echo "Running QUIC test: QD=$QUEUE_DEPTH, BS=$BLOCK_SIZE, Workload=$WORKLOAD, Time=${TEST_TIME}s..."
sudo ./spdk_nvme_perf -q $QUEUE_DEPTH -o $BLOCK_SIZE -w $WORKLOAD -t $TEST_TIME \
  -r "trtype:QUIC adrfam:IPv4 traddr:127.0.0.1 trsvcid:4420 subnqn:nqn.2016-06.io.spdk:cnode1 hostnqn:nqn.2016-06.io.spdk:host1" \
  --psk-path /tmp/nvme_quic_psk.key

echo "Test complete"
