#!/usr/bin/env bash
# Run SPDK NVMe-oF TCP Performance Tests
# Matches official SPDK performance test configuration

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPDK_DIR="$SCRIPT_DIR/.."
FIO_PLUGIN="$SPDK_DIR/build/fio/spdk_bdev"

# Test parameters (modify as needed)
IODEPTH="${IODEPTH:-128}"
RWMIXREAD="${RWMIXREAD:-100}"
NUMJOBS="${NUMJOBS:-4}"
RUNTIME="${RUNTIME:-300}"
RAMPTIME="${RAMPTIME:-60}"

echo "=========================================="
echo "SPDK NVMe-oF TCP Performance Test"
echo "=========================================="
echo ""
echo "Test Configuration:"
echo "  Queue Depth:  $IODEPTH"
echo "  Read Mix:     ${RWMIXREAD}%"
echo "  Jobs:         $NUMJOBS"
echo "  Ramp Time:    ${RAMPTIME}s"
echo "  Runtime:      ${RUNTIME}s"
echo ""

# Check if FIO plugin exists
if [ ! -f "$FIO_PLUGIN" ]; then
    echo "ERROR: FIO plugin not found at $FIO_PLUGIN"
    echo "Build it with: make -C $SPDK_DIR/examples/bdev/fio_plugin"
    exit 1
fi

# Check if bdev config exists
if [ ! -f "$SCRIPT_DIR/bdev_tcp_perf.json" ]; then
    echo "ERROR: bdev config not found at $SCRIPT_DIR/bdev_tcp_perf.json"
    exit 1
fi

# Create temporary FIO config
TMP_FIO_CONF=$(mktemp /tmp/fio_tcp_perf.XXXXXX.conf)
trap "rm -f $TMP_FIO_CONF" EXIT

cat > "$TMP_FIO_CONF" <<EOF
[global]
ioengine=$FIO_PLUGIN
spdk_conf=$SCRIPT_DIR/bdev_tcp_perf.json
thread=1
group_reporting=1
direct=1
norandommap=1
rw=randrw
rwmixread=$RWMIXREAD
bs=4k
iodepth=$IODEPTH
time_based=1
numjobs=$NUMJOBS
ramp_time=$RAMPTIME
runtime=$RUNTIME
percentile_list=50:90:99:99.5:99.9:99.99

[test0]
filename=Nvme0n1

[test1]
filename=Nvme1n1

[test2]
filename=Nvme2n1

[test3]
filename=Nvme3n1
EOF

echo "Generated FIO config: $TMP_FIO_CONF"
echo ""
echo "Starting FIO test..."
echo "=========================================="
echo ""

# Run FIO test
sudo fio "$TMP_FIO_CONF"

echo ""
echo "=========================================="
echo "Test complete!"
echo "=========================================="
echo ""
echo "To run with different parameters:"
echo "  IODEPTH=256 RWMIXREAD=70 RUNTIME=180 $0"
echo ""
echo "Queue depth tests from official benchmark:"
echo "  IODEPTH=128 $0  # Low"
echo "  IODEPTH=256 $0  # Medium"
echo "  IODEPTH=384 $0  # High"
echo ""
echo "Workload tests:"
echo "  RWMIXREAD=100 $0  # 100% read"
echo "  RWMIXREAD=70 $0   # 70% read, 30% write"
echo "  RWMIXREAD=0 $0    # 100% write"
echo ""
