#!/bin/bash

# Script to run SPDK NVMe perf for RDMA
# Usage: ./perf_test_rdma.sh [-q QUEUE_DEPTH] [-o BLOCK_SIZE] [-w WORKLOAD] [-t TEST_TIME] [additional options]

# Default values
QUEUE_DEPTH=16
BLOCK_SIZE=4096
WORKLOAD="randread"
TEST_TIME=15
RDMA_ADDR="10.0.0.3"  # ens0 with Soft-RoCE
RDMA_PORT="4420"
EXTRA_OPTS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -q) QUEUE_DEPTH="$2"; shift 2 ;;
    -o) BLOCK_SIZE="$2"; shift 2 ;;
    -w) WORKLOAD="$2"; shift 2 ;;
    -t) TEST_TIME="$2"; shift 2 ;;
    -a) RDMA_ADDR="$2"; shift 2 ;;
    *) EXTRA_OPTS="$EXTRA_OPTS $1"; shift ;;
  esac
done

cd ../build/bin

echo "Running RDMA test: QD=$QUEUE_DEPTH, BS=$BLOCK_SIZE, Workload=$WORKLOAD, Time=${TEST_TIME}s, Extra: $EXTRA_OPTS"
sudo ./spdk_nvme_perf -q $QUEUE_DEPTH -o $BLOCK_SIZE -w $WORKLOAD -t $TEST_TIME \
  -r "trtype:RDMA adrfam:IPv4 traddr:$RDMA_ADDR trsvcid:$RDMA_PORT subnqn:nqn.2016-06.io.spdk:cnode1" \
  $EXTRA_OPTS

echo "Test complete"
