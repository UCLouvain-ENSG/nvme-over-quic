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

### 5. Run the host (initiator side)

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
