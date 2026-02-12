#!/bin/bash
# compare_tcp_quic.sh - Run TCP and QUIC analysis and generate comparison

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-/etinfo/users2/soyong/Workspace/spdk/build/bin}"

echo "==================================="
echo "TCP vs QUIC Performance Comparison"
echo "==================================="
echo ""

# Check if log files exist
if [ ! -f "$BUILD_DIR/client_tcp_single.log" ]; then
    echo "ERROR: TCP log not found: $BUILD_DIR/client_tcp_single.log"
    exit 1
fi

if [ ! -f "$BUILD_DIR/client_quic_single.log" ]; then
    echo "ERROR: QUIC log not found: $BUILD_DIR/client_quic_single.log"
    exit 1
fi

# Run TCP analysis
echo "Analyzing TCP performance..."
python3 "$SCRIPT_DIR/analyze_tcp_complete.py" > "$BUILD_DIR/tcp_analysis.txt"
echo "  → Results saved to: $BUILD_DIR/tcp_analysis.txt"
echo ""

# Run QUIC analysis
echo "Analyzing QUIC performance..."
python3 "$SCRIPT_DIR/analyze_quic_complete.py" > "$BUILD_DIR/quic_analysis.txt"
echo "  → Results saved to: $BUILD_DIR/quic_analysis.txt"
echo ""

# Extract key metrics
echo "==================================="
echo "Summary Comparison"
echo "==================================="
echo ""

echo "TCP Performance:"
grep -E "Average latency:|P50 latency:|P95 latency:|P99 latency:|Inter-command gap:" "$BUILD_DIR/tcp_analysis.txt" | sed 's/^/  /'
echo ""

echo "QUIC Performance:"
grep -E "Average latency:|P50 latency:|P95 latency:|P99 latency:|Inter-command gap:" "$BUILD_DIR/quic_analysis.txt" | sed 's/^/  /'
echo ""

# Calculate tail latency ratio
TCP_P99=$(grep "P99 latency:" "$BUILD_DIR/tcp_analysis.txt" | awk '{print $3}')
QUIC_P99=$(grep "P99 latency:" "$BUILD_DIR/quic_analysis.txt" | awk '{print $3}')

if [ -n "$TCP_P99" ] && [ -n "$QUIC_P99" ]; then
    RATIO=$(echo "scale=2; $QUIC_P99 / $TCP_P99" | bc 2>/dev/null || echo "N/A")
    echo "P99 Latency Ratio (QUIC/TCP): ${RATIO}x"
    echo ""
fi

echo "==================================="
echo "Analysis complete!"
echo "Full reports:"
echo "  - TCP:  $BUILD_DIR/tcp_analysis.txt"
echo "  - QUIC: $BUILD_DIR/quic_analysis.txt"
echo "==================================="
