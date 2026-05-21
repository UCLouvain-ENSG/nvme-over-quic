# NVMe-over-QUIC (SPDK extension)

This is a extension of [SPDK](https://github.com/spdk/spdk) that adds NVMe-over-QUIC transport support.

For general SPDK documentation (build options, unit tests, Vagrant, hugepages, etc.) see [README_SPDK.md](README_SPDK.md).

## Table of Contents

* [Source Code](#source)
* [Prerequisites](#prerequisites)
* [Build](#build)
* [Setup & Running](#running)

<a id="source"></a>
## Source Code

Clone the repository and initialize **all submodules recursively** — quicly depends on
nested submodules (picotls, klib, picotest) that must also be checked out:

~~~{.sh}
git clone <this-repo-url> nvme-over-quic
cd nvme-over-quic
git submodule update --init --recursive
~~~

> **Note:** `git submodule update --init` without `--recursive` will leave
> `quicly/deps/picotls` empty, causing CMake errors like
> `INCLUDE could not find requested file: deps/picotls/cmake/boringssl-adjust.cmake`.

<a id="prerequisites"></a>
## Prerequisites

### 1. Base SPDK dependencies

~~~{.sh}
sudo ./scripts/pkgdep.sh
~~~

### 2. NVMe-over-QUIC additional dependencies

The upstream `scripts/pkgdep.sh` does **not** install everything needed on Ubuntu.
Run the supplemental script after it:

~~~{.sh}
sudo ./scripts/nvme_quic_pkgdep.sh
~~~

This installs the following packages missing from the upstream Ubuntu dep script:

| Package | Reason |
|---|---|
| `meson` | DPDK build system |
| `ninja-build` | DPDK build system |
| `python3-pyelftools` | Required by DPDK's meson configuration |
| `libbpf-dev` | eBPF headers for the SO_REUSEPORT UDP socket program |
| `clang` | Compiles the eBPF kernel program (`module/sock/udp/ebpf/`) |
| `libarchive-dev` | Linked by several SPDK apps and test binaries |

> **IPv6 note:** On systems with IPv6 disabled, `nginx` may fail to start during
> installation. This does **not** affect the SPDK build. Remove it if needed:
> `apt remove --purge nginx`

<a id="build"></a>
## Build

Use the provided build script, which cleans quicly, builds the eBPF program,
and runs the full SPDK make:

~~~{.sh}
./spdk_quic_build.sh
~~~

Or manually:

~~~{.sh}
# Build eBPF SO_REUSEPORT program first
make -C module/sock/udp/ebpf

# Build everything
mkdir -p ~/tmp && TMPDIR=~/tmp make -j$(nproc)
~~~

<a id="running"></a>
## Setup & Running

### 1. Allocate hugepages

SPDK requires 2 MB hugepages. `scripts/setup.sh` may exit with an error about
PCI drivers on VM/NVMe-over-Fabrics setups — that is harmless. Allocate hugepages
directly if needed:

~~~{.sh}
# Drop page cache first to allow contiguous allocation
echo 3 | sudo tee /proc/sys/vm/drop_caches
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
~~~

This allocates 2 GB (1024 × 2 MB). Verify with:

~~~{.sh}
grep HugePages_Total /proc/meminfo
~~~

### 2. Kernel network tuning (optional but recommended)

Run the tuning script to optimize socket buffers, TCP/UDP parameters, and NIC offloads before starting the target:

~~~{.sh}
sudo ./scripts/tuning_kernel.sh <interface>   # e.g. ens1f0np0 or lo
~~~

This sets:
- Flushes netfilter/iptables rules (eliminates packet filtering overhead)
- Socket buffer limits (rmem/wmem up to 256 MB)
- Network backlog and connection queue sizes
- TCP congestion control to cubic (for fair comparison with QUIC)
- UDP buffer minimums for high-throughput QUIC
- Memory overcommit (`vm.overcommit_memory=1`)
- CPU frequency governor set to `performance`
- NIC ring buffer sizes increased to 4096
- NIC offloads: GRO, GSO, TSO, UDP segmentation

### 3. Generate the PSK key (QUIC and TLS only)

QUIC and TLS transports require a shared pre-shared key (PSK) on both the
controller and host sides. Generate it once; it is reused across runs:

~~~{.sh}
./scripts/gen_psk.sh
~~~

This writes `scripts/nvme_psk.key` (NVMe TLS interchange format, mode 600).
The script re-execs itself under `sudo` automatically, because SPDK's keyring
module requires the key file to be owned by the same uid as the running process
(`nvmf_tgt` and `spdk_nvme_perf` both run as root).
Plain TCP skips this step. `host_run.sh` will also call this automatically
if the key is missing.

### 4. Start the target (controller side)

~~~{.sh}
sudo ./scripts/controller_run.sh -m 0x1
~~~

### 5. Attach the tansport

Bind the NVMe driver to vfio
~~~{.sh}
sudo ./setup.sh
~~~

~~~{.sh}
sudo ./nvmf_setup.sh -t quic -b /dev/nvme1
~~~

### 6. Run the host (initiator side)

~~~{.sh}
# QUIC transport (default example)
./scripts/host_run.sh -m quic -i 127.0.0.1 -c 0x1 -q 1 -o 4096 -w randread -t 30

# TLS over TCP
./scripts/host_run.sh -m tls -i 127.0.0.1 -c 0x1 -q 1 -o 4096 -w randread -t 30

# Plain TCP
./scripts/host_run.sh -m tcp -i 127.0.0.1 -c 0x1 -q 1 -o 4096 -w randread -t 30
~~~

Key `host_run.sh` options (extra args are passed to `spdk_nvme_perf`):

| Option | Description |
|---|---|
| `-m quic\|tls\|tcp` | Transport mode |
| `-i <ip>` | Target IP address |
| `-c <cpumask>` | CPU core mask (e.g. `0x1` for core 1, `0xF` for cores 0,1,2,3) |
| `-q <depth>` | I/O queue depth |
| `-o <size>` | I/O size in bytes |
| `-w <pattern>` | Workload: `randread`, `randwrite`, `randrw`, `read`, `write` |
| `-t <seconds>` | Test duration |
| `--save <file>` | Save output to a log file |

---

## QEMU / virtio-blk Test Setup

This setup chains SPDK subsystems to expose a remote NVMe as a `virtio-blk` device inside a QEMU guest:

```
nvmf_tgt ──(NVMf/TCP|TLS|QUIC)──> vhost ──(vhost-user)──> QEMU guest (/dev/vda)
```

Three transport modes are supported — start with TCP, then graduate to TLS and QUIC.

### Architecture

| Process | Binary | Role |
|---|---|---|
| NVMf target | `build/bin/nvmf_tgt` | Serves storage over NVMf |
| SPDK vhost | `build/bin/vhost` | NVMf initiator + vhost-user provider |
| QEMU | `qemu-system-x86_64` | VM sees remote NVMe as `/dev/vda` |

### Step-by-step (NVMe/TCP — then swap `-t tcp` for `tls` or `quic`)

**Terminal 1 — NVMf target:**

~~~{.sh}
# Cores 0 and 1 for the target
sudo ./scripts/controller_run.sh -m 0x3
~~~

**Terminal 2 — configure the target (run once the target is listening):**

~~~{.sh}
# -b m = malloc bdev (RAM, no real NVMe needed)
sudo ./scripts/nvmf_setup.sh -t tcp -b m

# TLS variant:
# sudo ./scripts/nvmf_setup.sh -t tls -b m

# QUIC variant:
# sudo ./scripts/nvmf_setup.sh -t quic -b m
~~~

**Terminal 3 — SPDK vhost (NVMf initiator + vhost-user provider):**

~~~{.sh}
# Use a different CPU core from nvmf_tgt
sudo ./scripts/vhost_run.sh -m 0x4
~~~

**Terminal 4 — connect vhost to the target:**

~~~{.sh}
sudo ./scripts/vhost_nvmf_setup.sh -t tcp

# TLS variant:
# sudo ./scripts/vhost_nvmf_setup.sh -t tls

# QUIC variant:
# sudo ./scripts/vhost_nvmf_setup.sh -t quic
~~~

**Terminal 5 — start the QEMU VM:**

~~~{.sh}
# Requires a Linux cloud image (e.g. Ubuntu Server .qcow2)
./scripts/qemu_start.sh --image /path/to/ubuntu.qcow2

# Optional: use hugepages for better vhost-user performance
./scripts/qemu_start.sh --image /path/to/ubuntu.qcow2 --hugepages
~~~

The remote NVMe device appears in the guest as `/dev/vda`. Run I/O inside the VM:

~~~{.sh}
sudo fio --ioengine=libaio --direct=1 --bs=4k --rw=randread \
         --iodepth=32 --filename=/dev/vda --runtime=30 --time_based --name=test
~~~

### Script reference

| Script | Description |
|---|---|
| `scripts/vhost_run.sh` | Start SPDK vhost application |
| `scripts/vhost_nvmf_setup.sh` | Connect vhost to NVMf target, expose via vhost socket |
| `scripts/qemu_start.sh` | Launch QEMU VM with virtio-blk backed by vhost |

#### `vhost_run.sh` options

| Option | Description |
|---|---|
| `-m <mask>` | CPU mask (e.g. `0x4` for core 2) |
| `--socket-dir <dir>` | Where to create vhost sockets (default: `/tmp/spdk_vhost`) |
| `--rpc-sock <path>` | Vhost RPC socket path (default: `/var/tmp/vhost.sock`) |
| `--gdb` | Wrap in GDB for crash analysis |

#### `vhost_nvmf_setup.sh` options

| Option | Description |
|---|---|
| `-t tcp\|tls\|quic` | Transport mode (required) |
| `-i <ip>` | NVMf target IP (default: `127.0.0.1`) |
| `-s <port>` | NVMf target port (default: `4420`) |
| `--rpc-sock <path>` | Vhost RPC socket (must match `vhost_run.sh`) |
| `--ctrlr <name>` | Vhost controller name / socket filename (default: `vhost.blk.0`) |

#### `qemu_start.sh` options

| Option | Description |
|---|---|
| `--image <path>` | OS disk image (qcow2/raw) |
| `--vhost-socket <path>` | Path to vhost socket (default: `/tmp/spdk_vhost/vhost.blk.0`) |
| `--memory <MB>` | VM RAM in MB (default: `2048`) |
| `--cpus <n>` | vCPU count (default: `2`) |
| `--ssh-port <port>` | Host port → VM SSH (default: `10022`) |
| `--hugepages` | Use `/dev/hugepages` for shared memory (better perf) |
| `--iso <path>` | Boot from ISO instead of image |
