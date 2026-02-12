#!/bin/bash

cd ../build/bin

echo "=========================================="
echo "TCP Performance Analysis"
echo "=========================================="
sudo perf report -i tcp_perf.data --stdio --percent-limit=1 | head -30

echo ""
echo ""
echo "=========================================="
echo "QUIC Performance Analysis"
echo "=========================================="
sudo perf report -i quic_perf.data --stdio --percent-limit=1 | head -30

echo ""
echo ""
echo "To view full reports interactively:"
echo "  sudo perf report -i tcp_perf.data"
echo "  sudo perf report -i quic_perf.data"
