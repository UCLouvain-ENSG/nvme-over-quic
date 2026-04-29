#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Install dependencies missing from scripts/pkgdep/ubuntu.sh
# required for NVMe-over-QUIC and eBPF builds.
#
# Run this after ./scripts/pkgdep.sh on Ubuntu systems.

set -e

apt-get install -y \
	meson \
	ninja-build \
	python3-pyelftools \
	libarchive-dev \
	libbpf-dev \
	clang

echo "All NVMe-over-QUIC dependencies installed."
