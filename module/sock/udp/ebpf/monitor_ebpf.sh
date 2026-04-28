#!/bin/bash

# Continuous monitoring of eBPF routing statistics

OUTPUT_FILE="${1:-ebpf_stats.log}"

echo "Writing eBPF statistics to: $OUTPUT_FILE"
echo "Press Ctrl+C to stop monitoring..."

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "ERROR: bpftool not found. Install with: sudo apt-get install linux-tools-common linux-tools-generic"
    exit 1
fi

# Check running with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo"
    exit 1
fi

# Clear the output file
> "$OUTPUT_FILE"

while true; do
    {
        echo "=== eBPF Routing Statistics ($(date)) ==="
        echo ""
    
    # Find the debug_stats map
    MAP_ID=$(bpftool map list 2>/dev/null | grep debug_stats | awk '{print $1}' | tr -d ':')
    
    if [ -z "$MAP_ID" ]; then
        echo "Waiting for eBPF program to be loaded... ($(date))" >> "$OUTPUT_FILE"
        sleep 2
        continue
    fi
    
    echo "Map ID: $MAP_ID"
    echo ""
    
    # Dump the entire map
    echo "--- Per-Index Counters (where packets were routed) ---"
    for i in 0 1 2 3; do
        val=$(bpftool map lookup id $MAP_ID key $i 0 0 0 2>/dev/null | grep -oP 'value: \K\d+' || echo "0")
        printf "  Index %d (shard_id %% 4 == %d): %10d packets\n" $i $i $val
    done
    
    echo ""
    echo "--- Per-Shard-ID Counters (what shard_id values were seen) ---"
    for i in 0 1 2 3; do
        key=$((10 + i))
        val=$(bpftool map lookup id $MAP_ID key $key 0 0 0 2>/dev/null | grep -oP 'value: \K\d+' || echo "0")
        printf "  Shard ID %d: %10d packets\n" $i $val
    done
    val=$(bpftool map lookup id $MAP_ID key 14 0 0 0 2>/dev/null | grep -oP 'value: \K\d+' || echo "0")
    printf "  Shard ID >= 4: %10d packets\n" $val
    
    echo ""
    echo "--- Overall ---"
    total=$(bpftool map lookup id $MAP_ID key 8 0 0 0 2>/dev/null | grep -oP 'value: \K\d+' || echo "0")
    errors=$(bpftool map lookup id $MAP_ID key 9 0 0 0 2>/dev/null | grep -oP 'value: \K\d+' || echo "0")
    failures=$(bpftool map lookup id $MAP_ID key 15 0 0 0 2>/dev/null | grep -oP 'value: \K\d+' || echo "0")
    
    printf "  Total packets:        %10d\n" $total
    printf "  Parse errors:         %10d\n" $errors
    printf "  Selection failures:   %10d\n" $failures
    
    echo ""
    echo "---"
    echo ""
    } >> "$OUTPUT_FILE"
    
    sleep 1
done
