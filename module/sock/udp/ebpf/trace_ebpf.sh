#!/bin/bash

# Monitor eBPF trace output (bpf_printk messages)

OUTPUT_FILE="${1:-ebpf_trace.log}"

echo "Writing eBPF traces to: $OUTPUT_FILE"
echo "Press Ctrl+C to stop monitoring..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo"
    exit 1
fi

# Check if trace_pipe exists
if [ ! -f /sys/kernel/debug/tracing/trace_pipe ]; then
    echo "ERROR: /sys/kernel/debug/tracing/trace_pipe not found!"
    echo "Make sure debugfs is mounted and CONFIG_DEBUG_FS is enabled."
    echo ""
    echo "Try: sudo mount -t debugfs none /sys/kernel/debug"
    exit 1
fi

# Clear the trace buffer first
echo > /sys/kernel/debug/tracing/trace

# Clear the output file
> "$OUTPUT_FILE"

# Monitor the trace pipe, filtering for our eBPF messages and writing to file
cat /sys/kernel/debug/tracing/trace_pipe | grep --line-buffered "bpf_trace_printk\|select_socket" >> "$OUTPUT_FILE"
