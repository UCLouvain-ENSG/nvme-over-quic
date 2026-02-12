#!/usr/bin/env python3
import re
import sys
from datetime import datetime

def parse_timestamp(line):
    """Extract timestamp from log line"""
    match = re.match(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\]', line)
    if match:
        return datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S.%f')
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_sock_poll_gaps.py <logfile>")
        sys.exit(1)
    
    logfile = sys.argv[1]
    
    with open(logfile, 'r') as f:
        lines = f.readlines()
    
    print("=" * 100)
    print("ANALYZING: spdk_sock_group_poll returned events -> next log gap")
    print("=" * 100)
    
    for i, line in enumerate(lines):
        if 'spdk_sock_group_poll returned 1 events' in line:
            ts1 = parse_timestamp(line)
            if ts1 and i + 1 < len(lines):
                next_line = lines[i + 1]
                ts2 = parse_timestamp(next_line)
                if ts2:
                    gap_ms = (ts2 - ts1).total_seconds() * 1000
                    
                    # Extract relevant info from next line
                    next_info = next_line.split('] ', 1)[1].strip() if '] ' in next_line else next_line.strip()
                    
                    if gap_ms > 1.0:  # More than 1ms gap
                        print(f"\n🔴 GAP: {gap_ms:.3f} ms")
                    else:
                        print(f"\n✅ GAP: {gap_ms:.3f} ms")
                    
                    print(f"  Line {i+1}: {ts1.strftime('%H:%M:%S.%f')} - {line.split('] ', 1)[1].strip() if '] ' in line else line.strip()}")
                    print(f"  Line {i+2}: {ts2.strftime('%H:%M:%S.%f')} - {next_info[:120]}")
                    
                    # Check if it's UDP epoll event
                    if 'UDP: epoll event' in next_line:
                        print(f"  ⚠️  WARNING: Large gap before epoll event log (should be INSIDE sock_group_poll!)")

if __name__ == '__main__':
    main()
