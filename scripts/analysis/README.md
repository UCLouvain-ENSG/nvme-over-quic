# SPDK Performance Analysis Scripts

This directory contains Python scripts for analyzing SPDK NVMe-oF performance logs.

## Analysis Scripts

### analyze_tcp_complete.py
**Purpose:** Complete TCP command latency analysis for queue depth 1 tests  
**Input:** client_tcp_single.log  
**Measures:** Command send → completion time for I/O queue READ operations  
**Output:** Per-command latencies, percentiles (P50/P95/P99), inter-command gaps  

**Usage:**
```bash
python3 analyze_tcp_complete.py > tcp_timing_analysis.txt
```

### analyze_quic_complete.py  
**Purpose:** Complete QUIC command latency analysis for queue depth 1 tests  
**Input:** client_quic_single.log  
**Measures:** Stream open (capsule_cmd_send) → completion time for I/O queue READ operations  
**Output:** Per-command latencies, percentiles (P50/P95/P99), inter-command gaps  

**Usage:**
```bash
python3 analyze_quic_complete.py > quic_timing_analysis.txt
```

### compare_tcp_quic.sh
**Purpose:** Automated comparison tool that runs both analyzers and generates side-by-side comparison  
**Usage:**
```bash
./compare_tcp_quic.sh
```

**Key Features:**
- Both scripts handle CID reuse correctly (sequential timestamp-based matching)
- Filter to only I/O queue (qid=1) commands, excluding admin queue
- Generate complete per-command latency reports with timing information
- Calculate inter-command gaps to identify serialization overhead
- Compare script extracts key metrics and calculates performance ratios

## Log File Format

All scripts expect SPDK debug logs with format:
```
[YYYY-MM-DD HH:MM:SS.ffffff] file.c:line:function: *LEVEL*: message
```

## Typical Workflow

1. Run TCP test with debug logging:
   ```bash
   cd /etinfo/users2/soyong/Workspace/spdk/build/bin
   sudo gdb --batch -ex 'set pagination off' \
     -ex 'run -q 1 -o 4096 -w randread -t 1 -T nvme --psk-path /tmp/nvme_psk.key \
          -r "trtype:TCP adrfam:IPv4 traddr:127.0.0.1 trsvcid:4420 \
              subnqn:nqn.2016-06.io.spdk:cnode1 hostnqn:nqn.2016-06.io.spdk:host1"' \
     -ex 'bt 15' -ex 'quit' ./spdk_nvme_perf 2>&1 | tee client_tcp_single.log
   ```

2. Run QUIC test with debug logging:
   ```bash
   sudo gdb --batch -ex 'set pagination off' \
     -ex 'run -q 1 -o 4096 -w randread -t 1 -T nvme --psk-path /tmp/nvme_quic_psk.key \
          -r "trtype:QUIC adrfam:IPv4 traddr:127.0.0.1 trsvcid:4420 \
              subnqn:nqn.2016-06.io.spdk:cnode1 hostnqn:nqn.2016-06.io.spdk:host1"' \
     -ex 'bt 15' -ex 'quit' ./spdk_nvme_perf 2>&1 | tee client_quic_single.log
   ```

3. Run automated comparison (recommended):
   ```bash
   cd /etinfo/users2/soyong/Workspace/spdk/scripts/analysis
   ./compare_tcp_quic.sh
   ```

   Or manually analyze each:
   ```bash
   python3 analyze_tcp_complete.py > ../../build/bin/tcp_analysis.txt
   python3 analyze_quic_complete.py > ../../build/bin/quic_analysis.txt
   ```

## Known Issues Detected

### QUIC "vecs Premature Free" Bug
The QUIC analysis consistently shows higher tail latencies (P95/P99) compared to TCP due to a race condition where NVMe requests are freed before QUIC send acknowledgments arrive. This causes intermittent 50-100ms stalls (4-5x normal latency).

**Symptoms:**
- Average latency similar to TCP (~19ms)
- P99 latency 3-4x higher than TCP (100ms vs 28ms)
- Random outlier commands with extreme latencies
- Non-deterministic behavior between test runs

**Root Cause:** Request completion (CQE) arrives before QUIC send ACK, causing premature `vecs` buffer free.

**Fix:** Only free `vecs` when BOTH `send_ack=1` AND `recv_cpl=1` in nvme_quic.c:nvme_quic_req_put()

## Requirements

- Python 3.x
- No external dependencies (uses only stdlib)
