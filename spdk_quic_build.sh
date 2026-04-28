#!/bin/bash
# Force clean rebuild of quicly library and relink binaries

cd /etinfo/users2/soyong/Workspace/spdk || exit 1

# Clean quicly to pick up source changes
echo "Cleaning quicly library..."
cd quicly && make clean 2>/dev/null
rm -f CMakeCache.txt
cd ..

# Remove binaries to force relinking with new quicly
echo "Removing binaries to force relink..."
rm -f build/bin/spdk_nvme_perf
rm -f build/lib/libspdk_nvme.a

# Build
echo "Building SPDK with quicly..."
mkdir -p ~/tmp && TMPDIR=~/tmp PYTHONWARNINGS=ignore make -j$(nproc) 2>&1
