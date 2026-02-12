#!/usr/bin/env python3
import re
import sys
from datetime import datetime
import os

# Get input filename from command line or use default
BUILD_DIR = "/etinfo/users2/soyong/Workspace/spdk/build/bin"

if len(sys.argv) > 1:
    input_filename = sys.argv[1]
    log_file = os.path.join(BUILD_DIR, input_filename)
    # Generate output filename: input.log -> input_analysis.txt
    base_name = os.path.splitext(input_filename)[0]
    output_file = os.path.join(BUILD_DIR, f"{base_name}_analysis.txt")
else:
    log_file = os.path.join(BUILD_DIR, "client_tcp_single.log")
    output_file = None  # Print to stdout

# Check if input file exists
if not os.path.exists(log_file):
    print(f"ERROR: Log file not found: {log_file}", file=sys.stderr)
    print(f"Usage: {sys.argv[0]} [logfilename]", file=sys.stderr)
    print(f"Example: {sys.argv[0]} client_tcp_single.log", file=sys.stderr)
    sys.exit(1)

# Track I/O queue (qid=1) READ commands with timestamps
io_sends = []  # [(timestamp, cid, line_num, line), ...] - only qid=1 sends
io_completes = []  # [(timestamp, cid, line_num, line), ...] - only completes that match I/O sends
all_lines = []  # [(timestamp, line_num, line), ...] - all lines with timestamps for gap analysis

# Patterns
send_pattern = re.compile(r'\[([\d\-: .]+)\].*READ sqid:1 cid:(\d+)')  # Only I/O queue reads
complete_pattern = re.compile(r'\[([\d\-: .]+)\].*nvme_complete_request.*opc=02.*cid=(\d+)')
# Timestamp pattern for all lines
timestamp_pattern = re.compile(r'\[([\d\-: .]+)\]')

# First pass: collect all lines with timestamps, sends, and completes
with open(log_file, 'r') as f:
    for line_num, line in enumerate(f, 1):
        # Check for timestamp
        ts_match = timestamp_pattern.match(line)
        if ts_match:
            timestamp_str = ts_match.group(1)
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
            all_lines.append((timestamp, line_num, line.strip()))
        
        # Check for send
        match = send_pattern.search(line)
        if match:
            timestamp_str = match.group(1)
            cid = int(match.group(2))
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
            io_sends.append((timestamp, cid, line_num, line.strip()))

# Redirect output to file if specified
if output_file:
    sys.stdout = open(output_file, 'w')
    print(f"# Analysis of: {os.path.basename(log_file)}", file=sys.stderr)
    print(f"# Output file: {output_file}", file=sys.stderr)

# Second pass: collect completions (from all_lines data we already have)
for ts, line_num, line in all_lines:
    match = complete_pattern.search(line)
    if match:
        timestamp_str = match.group(1)
        cid = int(match.group(2))
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
        io_completes.append((timestamp, cid, line_num, line.strip()))

print(f"Total I/O READ commands sent (qid=1): {len(io_sends)}")
print(f"Total READ completions found: {len(io_completes)}")
print(f"Total lines with timestamps: {len(all_lines)}")
print()

# Match completions to sends and find max gap within each command's time window
# For queue depth 1, they should be strictly in order
latencies = []
used_completions = set()  # Track which completions we've already matched

print("Analyzing timestamp gaps within each command window...")
for send_idx, (send_ts, send_cid, send_line_num, send_line) in enumerate(io_sends):
    # Find the completion with matching CID that comes AFTER this send
    # Don't assume order - search all completions (important for QD > 1)
    found = False
    best_match = None
    best_match_idx = -1
    
    for i, (comp_ts, comp_cid, comp_line_num, comp_line) in enumerate(io_completes):
        if i in used_completions:
            continue  # Already matched to another send
        if comp_cid == send_cid and comp_ts > send_ts:
            # Found a matching completion - take the earliest one
            if best_match is None or comp_ts < best_match[0]:
                best_match = (comp_ts, comp_cid, comp_line_num, comp_line)
                best_match_idx = i
    
    if best_match:
        comp_ts, comp_cid, comp_line_num, comp_line = best_match
        used_completions.add(best_match_idx)
        latency = (comp_ts - send_ts).total_seconds() * 1000  # ms
        
        # Find all lines between send and complete (by timestamp, not line number)
        # At high QD, line numbers can interleave between commands
        lines_in_window = [(ts, ln, l) for ts, ln, l in all_lines if send_ts <= ts <= comp_ts]
        
        # Find maximum gap between consecutive lines in this window
        max_gap = 0
        max_gap_line1 = None
        max_gap_line2 = None
        max_gap_linenum1 = 0
        max_gap_linenum2 = 0
        
        for j in range(len(lines_in_window) - 1):
            ts1, ln1, l1 = lines_in_window[j]
            ts2, ln2, l2 = lines_in_window[j + 1]
            gap = (ts2 - ts1).total_seconds() * 1000  # ms
            if gap > max_gap:
                max_gap = gap
                max_gap_line1 = l1
                max_gap_line2 = l2
                max_gap_linenum1 = ln1
                max_gap_linenum2 = ln2
        
        latencies.append((send_idx, send_cid, latency, send_ts, comp_ts, send_line_num, send_line, 
                        comp_line_num, comp_line, max_gap, max_gap_linenum1, max_gap_line1, 
                        max_gap_linenum2, max_gap_line2))
        found = True
    
    if not found:
        if send_idx < 10:  # Show first 10 warnings
            print(f"WARNING: No matching completion found for send #{send_idx}, CID={send_cid}")

print(f"Successfully matched pairs: {len(latencies)}")
print()

if latencies:
    avg_latency = sum(l[2] for l in latencies) / len(latencies)
    sorted_by_lat = sorted(latencies, key=lambda x: x[2])
    min_latency = sorted_by_lat[0][2]
    max_latency = sorted_by_lat[-1][2]
    
    print(f"Average latency: {avg_latency:.3f} ms")
    print(f"Min latency: {min_latency:.3f} ms (send #{sorted_by_lat[0][0]}, CID={sorted_by_lat[0][1]})")
    print(f"Max latency: {max_latency:.3f} ms (send #{sorted_by_lat[-1][0]}, CID={sorted_by_lat[-1][1]})")
    print()
    
    # Calculate percentiles  
    sorted_lats = [l[2] for l in sorted_by_lat]
    p50_idx = len(sorted_lats) // 2
    p95_idx = int(len(sorted_lats) * 0.95)
    p99_idx = int(len(sorted_lats) * 0.99)
    
    print(f"P50 latency: {sorted_lats[p50_idx]:.3f} ms")
    print(f"P95 latency: {sorted_lats[p95_idx]:.3f} ms")
    print(f"P99 latency: {sorted_lats[p99_idx]:.3f} ms")
    print()
    
    # Show all commands in order with max gap info
    print("All Commands (in time order):")
    print("="  * 120)
    for idx, cid, lat, send_ts, comp_ts, send_line_num, send_line, comp_line_num, comp_line, max_gap, _, _, _, _ in latencies:
        print(f"{idx+1:4d}. CID={cid:3d}: Latency={lat:8.3f}ms, MaxGap={max_gap:8.3f}ms (send={send_ts.strftime('%H:%M:%S.%f')}, complete={comp_ts.strftime('%H:%M:%S.%f')})")
    
    # Show detailed max gap points for commands with significant delays
    print()
    print("Maximum Gap Points Within Each Command Window:")
    print("="  * 120)
    gap_threshold = 1.0  # ms threshold for showing gaps
    high_gap_cmds = [l for l in latencies if l[9] > gap_threshold]  # l[9] is max_gap
    
    # Also show top 20 by maximum gap
    top_20_by_gap = sorted(latencies, key=lambda x: x[9], reverse=True)[:20]
    all_detailed = sorted(set(high_gap_cmds + top_20_by_gap), key=lambda x: x[9], reverse=True)
    
    if all_detailed:
        print(f"Showing {len(all_detailed)} commands with max gap > {gap_threshold}ms or in top 20:")
        print()
        for idx, cid, lat, send_ts, comp_ts, send_line_num, send_line, comp_line_num, comp_line, max_gap, gap_ln1, gap_l1, gap_ln2, gap_l2 in all_detailed:
            print(f"Command #{idx+1}, CID={cid}: Latency={lat:.3f}ms, MaxGap={max_gap:.3f}ms")
            print(f"  Send (Line {send_line_num}): {send_line}")
            print(f"  Complete (Line {comp_line_num}): {comp_line}")
            if max_gap > 0:
                print(f"  >>> MAX GAP ({max_gap:.3f}ms) between:")
                print(f"      Line {gap_ln1}: {gap_l1}")
                print(f"      Line {gap_ln2}: {gap_l2}")
            print("-" * 120)
    else:
        print(f"No commands exceed {gap_threshold}ms gap threshold.")
    
    # Summary of max gaps
    print()
    print("Maximum Gap Statistics:")
    print("=" * 100)
    max_gaps = [l[9] for l in latencies]  # l[9] is max_gap
    avg_max_gap = sum(max_gaps) / len(max_gaps)
    print(f"Average maximum gap within commands: {avg_max_gap:.3f} ms")
    print(f"Min maximum gap: {min(max_gaps):.3f} ms")
    print(f"Max maximum gap: {max(max_gaps):.3f} ms")
    
    # Calculate inter-command gaps
    print()
    print("Inter-command Analysis:")
    print("=" * 100)
    gaps = []
    for i in range(len(latencies) - 1):
        complete_time = latencies[i][4]
        next_send_time = latencies[i+1][3]
        gap = (next_send_time - complete_time).total_seconds() * 1000
        comp_line_num = latencies[i][7]
        comp_line = latencies[i][8]
        send_line_num = latencies[i+1][5]
        send_line = latencies[i+1][6]
        gaps.append((i, gap, complete_time, next_send_time, comp_line_num, comp_line, send_line_num, send_line))
    
    if gaps:
        avg_gap = sum(g[1] for g in gaps) / len(gaps)
        print(f"Average gap (complete to next send): {avg_gap:.3f} ms")
        print(f"Min gap: {min(g[1] for g in gaps):.3f} ms")
        print(f"Max gap: {max(g[1] for g in gaps):.3f} ms")

# Close output file if we opened one
if output_file:
    sys.stdout.close()
    print(f"Analysis complete! Output saved to: {output_file}", file=sys.__stdout__)
