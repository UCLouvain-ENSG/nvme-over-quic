# eBPF Reuseport Debugging Guide

## Overview

The eBPF program includes two debugging methods:

1. **bpf_printk()** - Real-time trace output (kernel trace pipe) ✅ ACTIVE
2. **debug_stats map** - Statistics counters for analysis

### bpf_printk() Output

The eBPF program now logs:
- When the program is called
- Packet type (long/short header)
- DCID length for long headers
- Extracted shard_id value
- Calculated routing index
- bpf_sk_select_reuseport() return value
- Any errors encountered

## Quick Start: Use bpf_printk() Tracing

**Step 1: Rebuild the eBPF program**
```bash
cd /etinfo/users2/soyong/Workspace/spdk/module/sock/udp/ebpf
make clean && make
```

**Step 2: In one terminal, start the trace monitor BEFORE starting SPDK:**
```bash
sudo ./trace_ebpf.sh
```

**Step 3: In another terminal, run SPDK with eBPF:**
```bash
cd /etinfo/users2/soyong/Workspace/spdk
export SPDK_UDP_EBPF_PATH=/etinfo/users2/soyong/Workspace/spdk/module/sock/udp/ebpf/reuseport_kern.o
# Run your nvmf_tgt or application
```

**Step 4: Send traffic and watch the trace output**

You should see messages like:
```
=== eBPF reuseport called! ===
first_byte=0xc0
Long header packet detected
Long header: dcid_len=16
Long header: shard_id=2 (from DCID[0])
Routing: shard_id=2 -> index=2
bpf_sk_select_reuseport returned: 0
```

## Troubleshooting with bpf_printk()

### No output at all

**Cause**: eBPF program is not being called by the kernel.

**Check**:
1. Is eBPF program loaded? `sudo bpftool prog show | grep sk_reuseport`
2. Is it attached to sockets? Check SPDK logs for "Attached eBPF program"
3. Is `SPDK_UDP_EBPF_PATH` environment variable set correctly?
4. Is debugfs mounted? `ls /sys/kernel/debug/tracing/trace_pipe`

### "trace_pipe not found" error

Mount debugfs:
```bash
sudo mount -t debugfs none /sys/kernel/debug
```

### See traces but routing is wrong

Check the trace output:
- What `shard_id` values are being extracted?
- What `index` values are being calculated?
- Is `bpf_sk_select_reuseport` returning 0 (success) or negative (error)?

## Alternative: Statistics Map (if bpf_printk doesn't work)
- **Keys 0-3**: Counters for each routing index (how many packets routed to each socket)
- **Keys 10-13**: Counters for shard_id 0-3 (what shard_id values are seen in packets)
- **Key 14**: Counter for shard_id >= 4 (overflow)
- **Key 8**: Total packets processed by eBPF
- **Key 9**: Parse errors (packet too short)
- **Key 15**: bpf_sk_select_reuseport() failures

## Rebuild Steps

1. **Rebuild the eBPF kernel program:**
   ```bash
   cd /etinfo/users2/soyong/Workspace/spdk/module/sock/udp/ebpf
   make clean
   make
   ```

2. **Rebuild SPDK (if you changed the C code):**
   ```bash
   cd /etinfo/users2/soyong/Workspace/spdk
   make clean
   make
   ```

3. **Run your SPDK application** (e.g., nvmf_tgt with eBPF enabled)

## Debugging Tools

### Option 1: Live Monitor (Recommended)

Watch statistics update in real-time:

```bash
cd /etinfo/users2/soyong/Workspace/spdk/module/sock/udp/ebpf
chmod +x monitor_ebpf.sh
sudo ./monitor_ebpf.sh
```

This will show:
- How many packets were routed to each index
- What shard_id values are being seen
- Any errors or failures

### Option 2: One-Time Snapshot

Get a single snapshot of statistics:

```bash
chmod +x debug_ebpf.sh
sudo ./debug_ebpf.sh
```

### Option 3: Manual Inspection with bpftool

```bash
# List all BPF maps
sudo bpftool map list

# Dump the debug_stats map (replace ID with actual map ID)
sudo bpftool map dump id <map_id>

# Dump the reuseport_array map
sudo bpftool map dump name reuseport_array

# Check attached programs
sudo bpftool prog show
```

## Expected Results

If eBPF routing is working correctly, you should see:

1. **Total packets > 0** - eBPF is being called
2. **Shard ID distribution matches what client sends** - CID parsing works
3. **Index distribution matches shard_id % 4** - Routing logic works
4. **Selection failures = 0** - bpf_sk_select_reuseport() succeeds

## Troubleshooting

### eBPF program not being called (Total packets = 0)

- Check if eBPF program is attached: `sudo bpftool prog show`
- Check if SO_ATTACH_REUSEPORT_EBPF succeeded (look at SPDK logs)
- Verify sockets are created with SO_REUSEPORT

### Selection failures > 0

- Socket array might not be populated correctly
- Check with: `sudo bpftool map dump name reuseport_array`

### Unexpected shard_id distribution

- Client might not be encoding shard_id correctly in DCID byte 0
- Add client-side logging to verify thread_id values

### Unexpected routing (index != shard_id % 4)

- This would indicate a bug in the eBPF program logic
- Check the debug_stats to see actual shard_id vs index values

## Alternative: Use bpf_printk (requires kernel debug)

If you need even more detailed debugging, you can add `bpf_printk()` calls to the eBPF program:

```c
bpf_printk("shard_id=%u, index=%u", shard_id, index);
```

Then read the trace:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Note: This requires CONFIG_DEBUG_FS and may impact performance.
