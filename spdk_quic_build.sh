#!/bin/bash
# Build (or rebuild) SPDK with QUIC support.
# Safe to run on a clean checkout as well as for iterative quicly rebuilds.

ROOTDIR="$(readlink -f "$(dirname "$0")")"
cd "$ROOTDIR"

# Initialize submodules if needed.
# quicly requires recursive init for its own sub-submodules (picotls, klib, picotest).
if [ ! -f dpdk/config/meson.build ] || [ ! -f quicly/deps/picotls/CMakeLists.txt ]; then
	echo "Initializing submodules..."
	git submodule update --init --recursive
fi

# Run configure if mk/config.mk does not yet exist.
if [ ! -f mk/config.mk ]; then
	echo "Running configure..."
	./configure
fi

# Clean quicly to pick up source changes
echo "Cleaning quicly library..."
if [ -f quicly/Makefile ]; then
	make -C quicly clean 2>/dev/null || true
fi
# Remove CMake-generated files so quicly is reconfigured on next build
rm -f quicly/CMakeCache.txt quicly/Makefile quicly/cmake_install.cmake
rm -rf quicly/CMakeFiles

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
