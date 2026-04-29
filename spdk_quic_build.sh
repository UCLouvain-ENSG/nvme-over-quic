#!/bin/bash
# Force clean rebuild of quicly library and relink binaries

# Clean quicly to pick up source changes
echo "Cleaning quicly library..."
cd quicly && make clean 2>/dev/null
rm -f CMakeCache.txt
cd ..

# Remove binaries to force relinking with new quicly
echo "Removing binaries to force relink..."
rm -f build/bin/spdk_nvme_perf
rm -f build/lib/libspdk_nvme.a

# Build eBPF SO_REUSEPORT program
echo "Building eBPF program..."
make -C module/sock/udp/ebpf

# Build
echo "Building SPDK with quicly..."
mkdir -p ~/tmp && TMPDIR=~/tmp PYTHONWARNINGS=ignore make -j$(nproc) 2>&1
