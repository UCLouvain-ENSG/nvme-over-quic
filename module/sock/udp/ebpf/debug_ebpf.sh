#!/bin/bash

# Debug script to read eBPF routing statistics

echo "=== eBPF Reuseport Debug Statistics ==="
echo ""

# Try to find the debug_stats map
MAP_ID=$(sudo bpftool map list | grep debug_stats | awk '{print $1}' | tr -d ':')

if [ -z "$MAP_ID" ]; then
    echo "ERROR: debug_stats map not found!"
    echo "Make sure the eBPF program is loaded and attached."
    echo ""
    echo "Available maps:"
    sudo bpftool map list
    exit 1
fi

echo "Found debug_stats map ID: $MAP_ID"
echo ""

# Read all entries
echo "Reading statistics..."
echo ""

# Function to read a specific key
read_stat() {
    local key=$1
    local desc=$2
    printf "%-40s : " "$desc"
    sudo bpftool map lookup id $MAP_ID key $key 2>/dev/null | grep value | awk '{printf "%d\n", strtonum($2)}'
}

echo "--- Routing Statistics ---"
read_stat "0 0 0 0" "Index 0 (shard_id % 4 == 0)"
read_stat "1 0 0 0" "Index 1 (shard_id % 4 == 1)"
read_stat "2 0 0 0" "Index 2 (shard_id % 4 == 2)"
read_stat "3 0 0 0" "Index 3 (shard_id % 4 == 3)"

echo ""
echo "--- Shard ID Distribution ---"
read_stat "10 0 0 0" "Shard ID 0"
read_stat "11 0 0 0" "Shard ID 1"
read_stat "12 0 0 0" "Shard ID 2"
read_stat "13 0 0 0" "Shard ID 3"
read_stat "14 0 0 0" "Shard ID >= 4"

echo ""
echo "--- Overall Statistics ---"
read_stat "8 0 0 0" "Total packets processed"
read_stat "9 0 0 0" "Packets too short (errors)"
read_stat "15 0 0 0" "bpf_sk_select_reuseport failures"

echo ""
echo "--- Socket Array Contents ---"
sudo bpftool map dump name reuseport_array 2>/dev/null

echo ""
echo "=== End Debug Statistics ==="
