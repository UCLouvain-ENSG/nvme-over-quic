# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An extension of [SPDK](https://github.com/spdk/spdk) adding a QUIC transport for NVMe-over-Fabrics (NVMf). QUIC runs over UDP with TLS via [quicly](https://github.com/h2o/quicly) + picotls. The repo is a fork of SPDK with new files added for the QUIC transport; the upstream SPDK codebase is otherwise largely untouched.

## Build

### First-time setup

```sh
# Install base SPDK dependencies
sudo ./scripts/pkgdep.sh
# Install QUIC-specific extras (meson, ninja, libbpf-dev, clang, libarchive-dev, etc.)
sudo ./scripts/pkgdep_nvme_quic.sh
# Initialize submodules (quicly requires --recursive for picotls/klib/picotest)
git submodule update --init --recursive
# Run configure (generates mk/config.mk)
./configure [--with-ebpf]   # --with-ebpf enables SO_REUSEPORT eBPF load-balancing
```

### Incremental / iterative builds

```sh
# Full build (clean quicly + rebuild eBPF program + SPDK make)
./spdk_quic_build.sh

# Manual incremental (when only SPDK C files changed, not quicly)
mkdir -p ~/tmp && TMPDIR=~/tmp make -j$(nproc)

# Rebuild only the eBPF SO_REUSEPORT program
make -C module/sock/udp/ebpf
```

`TMPDIR=~/tmp` is required because the default `/tmp` is often too small for the DPDK build.

## Code formatting

SPDK uses `astyle` with version 3.0.1–3.1 and the rules in `.astylerc` (K&R style, tab=8, 100-char lines). Run the format checker:

```sh
./scripts/check_format.sh
```

Astyle auto-fixes files in-place; if it reports "Formatted", re-stage those files.

## Running tests

SPDK has a full autotest suite (`./autotest.sh`), but for QUIC-specific work the typical workflow is manual:

### 1. Hugepages

```sh
echo 3 | sudo tee /proc/sys/vm/drop_caches
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

### 2. Start the NVMf target

```sh
sudo ./scripts/controller_run.sh -m 0x1          # runs nvmf_tgt under gdb
# optional: --no-gdb, -L nvmf_quic (log flag), --save <file>
```

### 3. Attach transport + bdev (in another terminal, while target waits for RPC)

```sh
sudo ./scripts/nvmf_setup.sh -t quic -b m        # malloc bdev, QUIC transport
# or:  -t tls -b n   (null bdev, TCP+TLS)
# or:  -t tcp -b r -p 0000:02:00.0  (real NVMe passthrough)
```

### 4. Run the host/initiator

```sh
# QUIC
./scripts/host_run.sh -m quic -i 127.0.0.1 -c 0x1 -q 1 -o 4096 -w randread -t 30
# TLS over TCP
./scripts/host_run.sh -m tls  -i 127.0.0.1 -c 0x1 -q 1 -o 4096 -w randread -t 30
# Plain TCP
./scripts/host_run.sh -m tcp  -i 127.0.0.1 -c 0x1 -q 1 -o 4096 -w randread -t 30
```

PSK key is generated automatically by `host_run.sh` if missing; you can also run `./scripts/gen_psk.sh` directly (writes `scripts/nvme_psk.key`, must be owned by root).

### Optional: kernel tuning before benchmarks

```sh
sudo ./scripts/tuning_kernel.sh <interface>   # e.g. ens1f0np0 or lo
```

## Architecture

### New files added by this project

| Path | Role |
|---|---|
| `lib/nvmf/quic.c` | NVMf **target** QUIC transport (~4400 lines). Implements `spdk_nvmf_transport_ops` and registers with `SPDK_NVMF_TRANSPORT_REGISTER(quic, ...)`. Handles listen/accept, per-qpair QUIC connections, stream multiplexing, R2T/C2H/H2C data flows. |
| `lib/nvme/nvme_quic.c` | NVMe **host** (initiator) QUIC transport (~3650 lines). Extends `spdk_nvme_ctrlr`/`spdk_nvme_qpair` with QUIC connection management, stream pool, PDU send/receive state machine. |
| `lib/nvme/nvme_quic_plaintext_cid.c` | Custom quicly CID encryptor: embeds `thread_id` (shard_id) in plaintext byte 0 so the eBPF program can route incoming UDP packets to the correct reactor. |
| `module/sock/udp/udp.c` | SPDK UDP socket module (`spdk_sock` interface over raw UDP, with batched `recvmmsg`/`sendmsg`, UDP GRO/GSO). Registered as socket implementation `"udp"`. |
| `module/sock/udp/ebpf/reuseport_kern.c` | eBPF `sk_reuseport` program: reads QUIC DCID byte 0 (shard_id) and selects the matching socket fd for SO_REUSEPORT multi-core load-balancing. |
| `include/spdk_internal/nvme_quic.h` | Shared header between host and target: `nvme_quic_stream` struct, UDP batch receive structs, PSK derivation (HKDF via OpenSSL), inline helpers. |

### Key data-flow concepts

**One QUIC connection = one NVMe qpair.** Each qpair creates a `quicly_conn_t` over a single UDP socket.

**One QUIC stream = one in-flight NVMe request.** The stream pool (`quic_streams`, sized `2 × queue_depth`) is pre-allocated per qpair; streams are returned to a free-list on completion.

**PDU layout on streams**: each stream carries either a command PDU (host→target) or a completion PDU (target→host). Write data uses a 2-vector send: `hdr_buf` for the NVMe command/R2T/completion (shared, never simultaneously live), `data_buf` for payload.

**eBPF multi-core**: when built with `--with-ebpf`, the target creates one UDP socket per reactor with `SO_REUSEPORT`. The eBPF program reads `DCID[0]` (shard_id) and routes to the correct socket. The CID is generated by `nvme_quic_plaintext_cid.c` which embeds `thread_id & 0xFF` in byte 0.

**TLS/PSK**: both host and target derive a TLS 1.3 PSK via HKDF (`tls13 nvme-tls-psk` label) from a shared interchange key (NVMe TLS interchange format, CRC-32 protected, base64-encoded). The `gen_psk.sh` script generates this key; `nvmf_setup.sh` loads it into SPDK's keyring.

### quicly build

quicly is a git submodule (`quicly/`). It is built separately via CMake by `quiclybuild/Makefile` (called as a SPDK sub-make dependency) and linked statically. After changing quicly source, run `./spdk_quic_build.sh` (it wipes the CMake cache) rather than plain `make`.

### SPDK socket abstraction

The UDP sock module (`"udp"`) sits between the NVMf QUIC transport and the OS. `nvmf_setup.sh` calls `sock_set_default_impl -i udp` at runtime before creating the QUIC transport. The posix and ssl modules handle TCP and TLS respectively.
