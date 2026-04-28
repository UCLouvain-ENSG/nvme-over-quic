#!/bin/bash

# Script to attach perf to running nvmf_tgt process
# Usage: ./perf_attach.sh -o <output.data> [-d duration] [perf options]

OUTPUT_FILE=""
DURATION=""
PERF_OPTS="-g"

while [[ $# -gt 0 ]]; do
    case $1 in
        -o)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -d)
            DURATION="$2"
            shift 2
            ;;
        -D|-F|-f|-c|-e|-P|--call-graph|--freq)
            PERF_OPTS="$PERF_OPTS $1 $2"
            shift 2
            ;;
        -a|-k|--all-cpus)
            PERF_OPTS="$PERF_OPTS $1"
            shift
            ;;
        *)
            PERF_OPTS="$PERF_OPTS $1"
            shift
            ;;
    esac
done

if [ -z "$OUTPUT_FILE" ]; then
    echo "Error: Output file required"
    echo "Usage: $0 -o <output.data> [-d duration] [perf options]"
    echo ""
    echo "Examples:"
    echo "  $0 -o server.data              # Profile until Ctrl+C"
    echo "  $0 -o server.data -d 30        # Profile for 30 seconds"
    echo "  $0 -o server.data -F 4000      # Custom sampling frequency"
    echo "  $0 -o server.data -d 30 -D 5   # Wait 5ms, then profile 30s"
    exit 1
fi

# Find nvmf_tgt PID (match pattern, not exact name)
NVMF_PID=$(pgrep -f "nvmf_tgt.*--wait-for-rpc" | head -1)

if [ -z "$NVMF_PID" ]; then
    echo "Error: nvmf_tgt process not found!"
    echo "Make sure nvmf_tgt is running first."
    echo ""
    echo "Running SPDK processes:"
    ps aux | grep -E "(nvmf_tgt|spdk)" | grep -v grep
    exit 1
fi

echo "Found nvmf_tgt with PID: $NVMF_PID"
echo "Output file: $OUTPUT_FILE"
echo "Perf options: $PERF_OPTS"

if [ -n "$DURATION" ]; then
    echo "Duration: ${DURATION}s"
    echo ""
    echo "Starting perf recording for $DURATION seconds..."
    sudo perf record -p "$NVMF_PID" -o "$OUTPUT_FILE" $PERF_OPTS sleep "$DURATION"
else
    echo "Duration: Until Ctrl+C"
    echo ""
    echo "Starting perf recording (press Ctrl+C to stop)..."
    sudo perf record -p "$NVMF_PID" -o "$OUTPUT_FILE" $PERF_OPTS
fi

echo ""
echo "Perf recording complete!"
echo "Data saved to: $OUTPUT_FILE"
echo ""
echo "To analyze:"
echo "  sudo perf report -i $OUTPUT_FILE"
echo "  sudo perf report -i $OUTPUT_FILE --no-children --no-inline"
