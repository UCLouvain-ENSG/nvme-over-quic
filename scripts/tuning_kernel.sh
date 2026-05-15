#!/usr/bin/env bash
set -e

IFACE=${1:-ens1f0np0}

echo "======================================="
echo " Network tuning for TCP + UDP workloads"
echo " Interface: $IFACE"
echo "======================================="

echo
echo "[0] Flushing netfilter rules (nft + iptables)"

nft flush ruleset || true
iptables -F || true
iptables -t nat -F || true
iptables -t mangle -F || true

echo
echo "[1] Increasing socket buffer limits"

sysctl -w net.core.rmem_max=268435456
sysctl -w net.core.wmem_max=268435456
sysctl -w net.core.rmem_default=134217728
sysctl -w net.core.wmem_default=134217728
sysctl -w net.core.optmem_max=25165824

echo
echo "[2] Network backlog and busy polling"

sysctl -w net.core.netdev_max_backlog=8192
sysctl -w net.core.busy_poll=0
sysctl -w net.core.busy_read=0

echo
echo "[3] TCP tuning"

sysctl -w net.ipv4.tcp_rmem="8192 1048576 33554432"
sysctl -w net.ipv4.tcp_wmem="8192 1048576 33554432"
sysctl -w net.ipv4.tcp_mem="268435456 268435456 268435456"
sysctl -w net.ipv4.tcp_max_syn_backlog=16384
sysctl -w net.core.somaxconn=4096
sysctl -w net.ipv4.tcp_sack=1
sysctl -w net.ipv4.tcp_timestamps=1
sysctl -w net.ipv4.tcp_fastopen=3
sysctl -w net.ipv4.tcp_notsent_lowat=131072
sysctl -w net.ipv4.tcp_congestion_control=cubic || true  # use cubic to match QUIC's CC for fair comparison
sysctl -w net.ipv4.route.flush=1

echo
echo "[4] UDP tuning"

sysctl -w net.ipv4.udp_rmem_min=65536
sysctl -w net.ipv4.udp_wmem_min=65536
# udp_mem: min/pressure/max in pages (4KB each); set to ~1GB min, ~2GB pressure, ~3GB max
sysctl -w net.ipv4.udp_mem="262144 524288 786432"
echo
echo "[5] Memory overcommit"

sysctl -w vm.overcommit_memory=1

echo
echo
echo "[6] CPU performance governor"

for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > "$cpu" 2>/dev/null || true
done

echo
echo "[7] Increase NIC ring buffer sizes"

ethtool -G "$IFACE" rx 4096 tx 4096 2>/dev/null || true

echo
echo "[8] Enable NIC offloads"

ethtool -K $IFACE gro on || true
ethtool -K $IFACE gso on || true
ethtool -K $IFACE tso on || true
# UDP GSO/GRO: helps QUIC/UDP batch processing (kernel 5.0+)
ethtool -K $IFACE tx-udp-segmentation on || true
ethtool -K $IFACE rx-gro-hw on || true


echo
echo "======================================="
echo " Network tuning completed"
echo "======================================="
