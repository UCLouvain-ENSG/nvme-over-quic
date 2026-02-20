#!/bin/bash

echo "=== Checking eBPF Attachment Status ==="
echo ""

echo "1. BPF Programs loaded:"
sudo bpftool prog show | grep -A 5 "sk_reuseport\|select_socket"
echo ""

echo "2. BPF Maps loaded:"
sudo bpftool map list | grep -E "reuseport_array|debug_stats"
echo ""

echo "3. Sockets listening on port 4420:"
sudo ss -tulpn | grep 4420
echo ""

echo "4. Detailed socket info with SO_ATTACH_REUSEPORT_EBPF:"
# Get socket inodes
INODES=$(sudo ss -tulpn | grep 4420 | awk '{print $7}' | grep -oP 'ino:\K\d+')
echo "Socket inodes: $INODES"
echo ""

echo "5. Check if eBPF prog is actually attached to sockets:"
for pid in $(pgrep nvmf_tgt || pgrep reactor); do
    echo "Process: $pid"
    sudo ls -la /proc/$pid/fd/ 2>/dev/null | grep socket | head -5
done
echo ""

echo "6. Kernel ring buffer (check for eBPF errors):"
sudo dmesg | tail -20 | grep -i "bpf\|ebpf" || echo "No recent BPF messages"
