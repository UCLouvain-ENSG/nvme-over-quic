#!/bin/bash

# Script to run SPDK NVMe perf for QUIC
# Usage: ./perf_test_quic.sh [-q QUEUE_DEPTH] [-o BLOCK_SIZE] [-w WORKLOAD] [-t TEST_TIME] [-L LOG_FLAG] [additional options]

# Default values
QUEUE_DEPTH=16
BLOCK_SIZE=4096
WORKLOAD="randread"
TEST_TIME=15
LOGFLAG=""
EXTRA_OPTS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -q) QUEUE_DEPTH="$2"; shift 2 ;;
    -o) BLOCK_SIZE="$2"; shift 2 ;;
    -w) WORKLOAD="$2"; shift 2 ;;
    -t) TEST_TIME="$2"; shift 2 ;;
    -L) LOGFLAG="-L $2"; shift 2 ;;
    *) EXTRA_OPTS="$EXTRA_OPTS $1"; shift ;;
  esac
done

cd ../build/bin

echo "Running QUIC test: QD=$QUEUE_DEPTH, BS=$BLOCK_SIZE, Workload=$WORKLOAD, Time=${TEST_TIME}s, Extra: $EXTRA_OPTS"
[ -n "$LOGFLAG" ] && echo "  Log flag enabled: ${LOGFLAG#-L }"
# sudo ./spdk_nvme_perf -q $QUEUE_DEPTH -o $BLOCK_SIZE -w $WORKLOAD -t $TEST_TIME \
#   -r "trtype:QUIC adrfam:IPv4 traddr:127.0.0.1 trsvcid:4420 subnqn:nqn.2016-06.io.spdk:cnode1 hostnqn:nqn.2016-06.io.spdk:host1" \
#   --psk-path /tmp/nvme_quic_psk.key $EXTRA_OPTS


sudo perf record -g --call-graph dwarf ./spdk_nvme_perf $LOGFLAG -q $QUEUE_DEPTH -o $BLOCK_SIZE -w $WORKLOAD -t $TEST_TIME \
  -r "trtype:QUIC adrfam:IPv4 traddr:127.0.0.1 trsvcid:4420 subnqn:nqn.2016-06.io.spdk:cnode1 hostnqn:nqn.2016-06.io.spdk:host1" \
  --psk-path /tmp/nvme_quic_psk.key $EXTRA_OPTS


echo "Test complete"
